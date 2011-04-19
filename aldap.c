/*	$Id: aldap.c,v 1.10 2011-01-11 08:58:10 martinh Exp $ */
/*	$OpenBSD: aldap.c,v 1.26 2010/07/21 17:32:12 martinh Exp $ */

/*
 * Copyright (c) 2010 Martin Hedenfalk <martinh@openbsd.org>
 * Copyright (c) 2008 Alexander Schrijver <aschrijver@openbsd.org>
 * Copyright (c) 2006, 2007 Marc Balmer <mbalmer@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netdb.h>

#include <errno.h>
#include <fcntl.h>
#include <imsg.h>
#include <inttypes.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vis.h>

#include <openssl/err.h>
#include <openssl/engine.h>

#include "aldap.h"

#define VERSION		3
#define SSL_CIPHERS	"HIGH"
#define SSL_TIMEOUT	300

/* The maximum size of the input buffer. */
#define MAX_IBUF_SIZE	16*1024*1024

#define LDAP_EXT_REQ_START_TLS		"1.3.6.1.4.1.1466.20037"
#define LDAP_CONTROL_PAGED_RESULTS	"1.2.840.113556.1.4.319"

static void	 aldap_disconnect(struct aldap *ld);
static int	 aldap_connect_next(struct aldap *ld);
static int	 aldap_continue_connect(struct aldap *ld);
static int	 aldap_consume(struct aldap *ld, int max_msg);
static int	 aldap_ssl_check(struct aldap *ld, int ret, const char *where);

static struct aldap_message	*aldap_parse(struct aldap *ld, struct ber_element *root);
static struct aldap_message	*aldap_find_msg(struct aldap *ld, int msgid);

static struct ber_element	*ldap_parse_search_filter(struct ber_element*, const char *);
static struct ber_element	*ldap_do_parse_search_filter(struct ber_element*, const char **);

static void	 ibuf_drain(struct ibuf *buf, size_t nbytes);
static char	**aldap_get_stringset(struct ber_element *);
static char	*utoa(char *);
static char	*parseval(const char *p, size_t len);

static int	 ssl_initialized = 0;

#ifdef DEBUG
# define DPRINTF(...)	do { fprintf(stderr, "%s:%d: ", __func__, __LINE__); \
			     fprintf(stderr, __VA_ARGS__); \
			     fprintf(stderr, "\n"); } while(0)
# define LDAP_DEBUG(x, y)	do { fprintf(stderr, "*** " x "\n"); \
				     if (y == NULL) fprintf(stderr, "NULL\n"); \
				     else ldap_debug_elements(y); } while (0)
# define SSL_DEBUG(where)	do { fprintf(stderr, "SSL error in %s:\n", (where)); \
				     ERR_print_errors_fp(stderr); } while (0)
#else
# define DPRINTF(x...)	do { } while (0)
# define LDAP_DEBUG(x, y)	do { } while (0)
# define SSL_DEBUG(where)	do { } while (0)
#endif

static void
aldap_disconnect(struct aldap *ld)
{
	if (ld->fd != -1)
		close(ld->fd);
	ld->fd = -1;
	ld->connected = 0;
	ld->ssl_connected = 0;
	if (ld->ssl)
		SSL_free(ld->ssl);
	ld->ssl = NULL;
	ld->err = ALDAP_ERR_CONNECTION_CLOSED;
}

int
aldap_close(struct aldap *ld)
{
	struct aldap_message *msg;

	while ((msg = TAILQ_FIRST(&ld->msgq)) != NULL) {
		TAILQ_REMOVE(&ld->msgq, msg, next);
		aldap_freemsg(msg);
	}

	aldap_disconnect(ld);

	if (ld->r != NULL)
		ibuf_free(ld->r);

	msgbuf_clear(&ld->w);
	free(ld);

	return (0);
}

struct aldap *
aldap_new(void)
{
	struct aldap *ld;

	if ((ld = calloc(1, sizeof(*ld))) == NULL)
		return NULL;

	ld->fd = -1;
	TAILQ_INIT(&ld->msgq);
	ld->r = ibuf_dynamic(4096, MAX_IBUF_SIZE);
	msgbuf_init(&ld->w);
	ld->w.fd = -1;

	return ld;
}

struct aldap *
aldap_init(int fd)
{
	struct aldap	*ld;
	int		 flags;

	if ((ld = aldap_new()) == NULL)
		return NULL;

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	ld->fd = fd;
	ld->w.fd = fd;
	ld->connected = 1;

	return ld;
}

struct aldap *
aldap_open(const char *hostname, int port)
{
	struct addrinfo	 hints, *ai0;
	struct aldap	*ld;
	char		*servname;
	int		 err;

	if (port > 0)
		err = asprintf(&servname, "%d", port);
	else
		err = asprintf(&servname, "ldap");
	if (err == -1) {
		DPRINTF("asprintf: %s", strerror(errno));
		return NULL;
	}

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(hostname, servname, &hints, &ai0);
	free(servname);
	if (err != 0) {
		DPRINTF("%s: %s", hostname, gai_strerror(err));
		return NULL;
	}

	if ((ld = aldap_new()) == NULL) {
		freeaddrinfo(ai0);
		return NULL;
	}

	aldap_connect(ld, ai0);
	if (aldap_flush(ld, 10*1000) == -1) {
		aldap_close(ld);
		return NULL;
	}

	return ld;
}

struct aldap *
aldap_open_local(const char *filename)
{
	struct sockaddr_un	 un;
	struct aldap		*ld;
	int			 fd, flags;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		DPRINTF("socket: %s", strerror(errno));
		return NULL;
	}

	if ((ld = aldap_new()) == NULL) {
		close(fd);
		return NULL;
	}

	bzero(&un, sizeof(un));
	if (strlcpy(un.sun_path, filename, sizeof(un.sun_path)) >= sizeof(un.sun_path)) {
		DPRINTF("socket filename truncated");
		errno = EINVAL;
		free(ld);
		return NULL;
	}
	un.sun_family = AF_UNIX;

	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) == -1) {
		DPRINTF("connect: %s", strerror(errno));
		free(ld);
		return NULL;
	}

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	ld->fd = fd;
	ld->w.fd = fd;
	ld->connected = 1;

	return ld;
}

int
aldap_try_connect(struct aldap *ld, int fd, struct sockaddr *sa, socklen_t slen)
{
	char	 host[NI_MAXHOST], serv[NI_MAXSERV];
	int	 err, flags;

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	err = getnameinfo(sa, slen, host, sizeof(host), serv, sizeof(serv),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (err != 0) {
		DPRINTF("getnameinfo: %s", gai_strerror(err));
		return -1;
	}

	DPRINTF("connecting to %s:%s", host, serv);
	if (connect(fd, sa, slen) == -1)
		if (errno != EINPROGRESS) {
			DPRINTF("connect: %s", strerror(errno));
			return -1;
		}

	ld->fd = fd;
	ld->w.fd = fd;
	ld->connected = 0;

	return 0;
}

static int
aldap_connect_next(struct aldap *ld)
{
	int fd;

	if (ld->fd != -1)
		close(ld->fd);
	ld->fd = -1;

	if (ld->ai == NULL)
		ld->ai = ld->ai0;
	else
		ld->ai = ld->ai->ai_next;

	for (; ld->ai != NULL; ld->ai = ld->ai->ai_next) {
		fd = socket(ld->ai->ai_family, ld->ai->ai_socktype,
		    ld->ai->ai_protocol);
		if (fd == -1) {
			DPRINTF("socket: %s", strerror(errno));
			continue;
		}

		if (aldap_try_connect(ld, fd, ld->ai->ai_addr,
		    ld->ai->ai_addrlen) == 0)
			break;

		close(fd);
	}

	if (ld->ai == NULL) {
		/* No address succeeded. */
		DPRINTF("no address succeeded");
		if (ld->ai0 != NULL)
			freeaddrinfo(ld->ai0);
		errno = ECONNREFUSED;
		return -1;
	}

	return 0;
}

static int
aldap_continue_connect(struct aldap *ld)
{
	int		 err;
	socklen_t	 len = sizeof(err);

	DPRINTF("continue connecting on fd %d", ld->fd);

	if (getsockopt(ld->fd, SOL_SOCKET, SO_ERROR, &err, &len) == -1) {
		DPRINTF("getsockopt: %s", strerror(errno));
		err = -1;
	} else if (err != 0)
		DPRINTF("async connect failed: %s", strerror(err));

	if (err != 0)
		return aldap_connect_next(ld);

	DPRINTF("connected on fd %d", ld->fd);
	ld->connected = 1;
	if (ld->ai0 != NULL)
		freeaddrinfo(ld->ai0);

	return 0;
}

int
aldap_connect(struct aldap *ld, struct addrinfo *ai0)
{
	if (ld->fd != -1) {
		/* already connected */
		aldap_disconnect(ld);
	}

	ld->ai0 = ai0;
	return aldap_connect_next(ld);
}

int
aldap_poll(struct aldap *ld, short ev, int *timeout)
{
	struct timeval	 t0, t, td;
	struct pollfd	 pfd[1];
	int		 nfds, ms, ms_delta;

	if (ld->fd == -1) {
		DPRINTF("no socket");
		return -1;
	}

	bzero(&pfd, sizeof(pfd));
	pfd[0].fd = ld->fd;
	pfd[0].events = ev;

	if (!ld->connected || ld->w.queued > 0)
		pfd[0].events |= POLLOUT;

	pfd[0].events |= ld->ssl_ev;
	ld->ssl_ev = 0;

	if (!ld->connected)
		pfd[0].events &= ~POLLIN;

	if (timeout == NULL)
		ms = -1;
	else {
		ms = *timeout;
		gettimeofday(&t0, NULL);
	}

	DPRINTF("polling fd %d for%s%s at most %dms",
	    ld->fd,
	    (pfd[0].events & POLLIN) ? " read" : "",
	    (pfd[0].events & POLLOUT) ? " write" : "",
	    ms);
	nfds = poll(pfd, 1, ms);
	if (nfds == -1 || (pfd[0].revents & (POLLERR|POLLHUP|POLLNVAL))) {
		if ((pfd[0].revents & POLLERR) && !ld->connected)
			return aldap_continue_connect(ld);
		DPRINTF("poll error: %s", strerror(errno));
		return -1;
	}

	if (nfds == 0) {
		DPRINTF("poll timeout after %dms", ms);
		if (timeout != NULL)
			*timeout = 0;
		return 0;
	}

	if (pfd[0].revents & POLLIN) {
		if (ld->ssl && !ld->ssl_connected) {
			if (aldap_ssl_connect(ld) == -1)
				return -1;
		} else if (aldap_read(ld) == -1)
			return -1;
	}

	if (pfd[0].revents & POLLOUT) {
		if (ld->ssl && !ld->ssl_connected) {
			if (aldap_ssl_connect(ld) == -1)
				return -1;
		} else if (ld->connected) {
			if (aldap_write(ld) == -1)
				return -1;
		} else if (aldap_continue_connect(ld) == -1)
			return -1;
	}

	/* Got here before the timeout, update it.
	 */
	if (timeout != NULL) {
		gettimeofday(&t, NULL);
		timersub(&t, &t0, &td);
		ms_delta = td.tv_sec * 60 + td.tv_usec / 1000;
		*timeout = ms - ms_delta;
		DPRINTF("%dms left of the timeout", *timeout);
	}

	return 0;
}

int
aldap_write(struct aldap *ld)
{
	struct ibuf	*buf;
	int		 ret;

	DPRINTF("writing %u queued bufs", ld->w.queued);
	if (ld->ssl) {
		for (;;) {
			if ((buf = TAILQ_FIRST(&ld->w.bufs)) == NULL)
				return 0;

			ret = SSL_write(ld->ssl, buf->buf + buf->rpos,
			    buf->wpos - buf->rpos);
			if (ret <= 0)
				return aldap_ssl_check(ld, ret, "SSL_write");
			msgbuf_drain(&ld->w, ret);
		}
	} else {
		if (ibuf_write(&ld->w) != 0) {
			DPRINTF("ibuf_write: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}

int
aldap_read(struct aldap *ld)
{
	char		 buf[4096];
	ssize_t		 ret;

	do {
		if (ld->ssl) {
			ret = SSL_read(ld->ssl, buf, sizeof(buf));
			DPRINTF("SSL_read(%d) returned %zd", ld->fd, ret);
			if (ret <= 0)
				return aldap_ssl_check(ld, ret, "SSL_read");
		} else {
			ret = read(ld->fd, buf, sizeof(buf));
			DPRINTF("read(%d) returned %zd", ld->fd, ret);
			if (ret == -1) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN)
					break;
				DPRINTF("read: %s", strerror(errno));
				return -1;
			}
		}

		if (ret == 0) {		/* connection closed */
			aldap_disconnect(ld);
			return -1;
		}

		if (ibuf_add(ld->r, buf, ret) == -1)
			break;
	} while (ret == sizeof(buf));

	return 0;
}

unsigned long
aldap_application(struct ber_element *elm)
{
	return BER_TYPE_OCTETSTRING;
}

/*
 * Reads responses from the input buffer and puts them on the message queue.
 * Drains the input buffer of complete commands.
 * Returns number of messages queued (possibly 0).
 */
static int
aldap_consume(struct aldap *ld, int max_msg)
{
	struct ber		 ber;
	struct ber_element	*root;
	size_t			 nbytes = 0;
	int			 nmsg = 0;

	bzero(&ber, sizeof(ber));
	ber_set_application(&ber, aldap_application);
	ber_set_readbuf(&ber, ld->r->buf, ibuf_size(ld->r));

	while (ber_left(&ber) > 0) {
		root = ber_read_elements(&ber, NULL);
		if (root == NULL && errno == ECANCELED) {
			/* Incomplete BER struct, wait for more. */
			DPRINTF("incomplete BER struct, want more data");
			break;
		}

		nbytes = ber.br_rptr - ber.br_rbuf;

		if (root == NULL)
			DPRINTF("failed to read BER struct: %s", strerror(errno));
		else if (aldap_parse(ld, root) != NULL && ++nmsg >= max_msg)
			break;
	}

	ibuf_drain(ld->r, nbytes);
	return nmsg;
}

static void
ibuf_drain(struct ibuf *buf, size_t nbytes)
{
	if (nbytes <= ibuf_size(buf)) {
		buf->wpos -= nbytes;
		buf->rpos = 0;
		bcopy(buf->buf + nbytes, buf->buf, buf->wpos);
	}
}

/*
 * Returns a parsed LDAP message with the given message id,
 * or NULL if none found. Pass -1 as msgid to return any message.
 * The message must already have been read and put on the msgq with aldap_read.
 */
static struct aldap_message *
aldap_find_msg(struct aldap *ld, int msgid)
{
	struct aldap_message	*msg;

	TAILQ_FOREACH(msg, &ld->msgq, next)
		if (msgid == -1 || msg->msgid == msgid) {
			TAILQ_REMOVE(&ld->msgq, msg, next);
			return msg;
		}

	return NULL;
}

/*
 * Waits for a reply to the given message id, or any reply if msgid is -1.
 * Blocks if timeout is a NULL pointer, otherwise it specifies the timeout in
 * milliseconds. Returns the response code of the found message, or -1 if no
 * message was placed in *res. Timeout can be detected by checking if *timeout
 * is zero. Unless res is a NULL pointer, returned message in *res must be
 * freed with aldap_freemsg.
 */
int
aldap_result(struct aldap *ld, int msgid, int *timeout,
    struct aldap_message **res)
{
	struct aldap_message	*msg;
	int			 done = 0;
	int			 code;

	DPRINTF("waiting for response to msgid %d", msgid);

	for (;;) {
		if ((msg = aldap_find_msg(ld, msgid)) != NULL) {
			code = msg->code;
			if (res == NULL)
				aldap_freemsg(msg);
			else
				*res = msg;
			return code;
		}

		if (done)
			break;

		if (aldap_consume(ld, 1) <= 0) {
			if (aldap_poll(ld, POLLIN, timeout) == -1)
				return -1;
			if (timeout != NULL && *timeout == 0)
				done = 1;
		}
	}

	return -1;	/* timeout */
}

int
aldap_flush(struct aldap *ld, int timeout)
{
	int ms;
	int connecting = !ld->connected;

	do {
		ms = timeout;
		if (aldap_poll(ld, 0, ms == -1 ? NULL : &ms) == -1)
			return -1;
		if (connecting && ms == 0)
			if (aldap_connect_next(ld) == -1)
				return -1;
	} while (connecting ? !ld->connected : ld->w.queued);
	return 0;
}

int
aldap_enqueue(struct aldap *ld, struct ber_element *root)
{
	struct ibuf	*buf = NULL;

	LDAP_DEBUG("request", root);

	if (ld->connected)
		buf = ber_write_elements(root);
	ber_free_elements(root);

	if (buf == NULL)
		return (-1);

	DPRINTF("queueing %zd bytes on fd %d for msgid %d",
	    ibuf_size(buf), ld->fd, ld->msgid);

	ibuf_close(&ld->w, buf);
	return ld->msgid;
}

int
aldap_bind(struct aldap *ld, const char *binddn, const char *bindcred)
{
	struct ber_element *root;

	if (binddn == NULL)
		binddn = "";
	if (bindcred == NULL)
		bindcred = "";

	root = ber_printf(NULL, "{d{tdsst}}", ++ld->msgid,
	    BER_CLASS_APP, (unsigned long)LDAP_REQ_BIND, 3, binddn, bindcred,
	    BER_CLASS_CONTEXT, (unsigned long)LDAP_AUTH_SIMPLE);
	if (root == NULL) {
		ld->err = ALDAP_ERR_OPERATION_FAILED;
		return -1;
	}

	return aldap_enqueue(ld, root);
}

int
aldap_bind_s(struct aldap *ld, const char *binddn, const char *bindcred)
{
	int msgid;

	if ((msgid = aldap_bind(ld, binddn, bindcred)) == -1)
		return -1;
	return aldap_result(ld, msgid, NULL, NULL);
}

int
aldap_unbind(struct aldap *ld)
{
	struct ber_element *root;

	root = ber_printf(NULL, "{d{t}}", ++ld->msgid,
	    BER_CLASS_APP, LDAP_REQ_UNBIND_30);
	if (root == NULL) {
		ld->err = ALDAP_ERR_OPERATION_FAILED;
		return -1;
	}

	return aldap_enqueue(ld, root);
}

void
aldap_unbind_s(struct aldap *ld)
{
	if (aldap_unbind(ld) == 0)
		aldap_flush(ld, -1);
	aldap_close(ld);
}

int
aldap_search(struct aldap *ld, struct aldap_search *params)
{
	struct ber_element	*root, *elm;
	const char		*filter;
	int			 i;

	root = ber_printf(NULL, "{d{tsEEddb", ++ld->msgid, BER_CLASS_APP,
	    (unsigned long)LDAP_REQ_SEARCH, params->basedn,
	    (long long)params->scope, (long long)LDAP_DEREF_NEVER,
	    params->sizelimit, params->timelimit, params->typesonly);
	if (root == NULL) {
		ld->err = ALDAP_ERR_OPERATION_FAILED;
		return -1;
	}

	filter = params->filter;
	if (filter == NULL)
		filter = "(objectClass=*)";

	if ((elm = ldap_parse_search_filter(NULL, filter)) == NULL) {
		ld->err = ALDAP_ERR_PARSER_ERROR;
		goto fail;
	}

	if (ber_printf(root, "e{", elm) == NULL)
		goto fail;

	if (params->attributes[0] == NULL) {
		if (ber_printf(root, "s", "*") == NULL)
			goto fail;
	} else {
		for (i = 0; i < ALDAP_MAXATTR && params->attributes[i] != NULL; i++)
			if (ber_printf(root, "s", params->attributes[i]) == NULL)
				goto fail;
	}

	if (ber_printf(root, "}}") == NULL)
		goto fail;

	if (params->controls[0] != NULL) {
		if (ber_printf(root, "{t", BER_CLASS_CONTEXT, 0UL) == NULL)
			goto fail;
		for (i = 0; i < ALDAP_MAXCTRL && params->controls[i]; i++) {
			if (ber_printf(root, "e", params->controls[i]) == NULL)
				goto fail;
			params->controls[i] = NULL;
		}
		if (ber_printf(root, "}") == NULL)
			goto fail;
	}

	return aldap_enqueue(ld, root);

fail:
	if (root != NULL)
		ber_free_elements(root);
	return -1;
}

int
aldap_get_control(struct aldap_message *msg, const char *oid, struct ber_val **val)
{
	struct ber_element	*elm, *cval;
	char			*coid;
	void			*cbuf;
	size_t			 csiz;
	int			 crit;

	LDAP_DEBUG("msg->controls", msg->controls);

	if (ber_scanf(msg->controls, "{e", &elm) == -1)
		return -1;

	for (; elm; elm = elm->be_next) {
		/* Criticality has default value FALSE (and ignored). */
		if (ber_scanf(elm, "{sbe}", &coid, &crit, &cval) == -1 &&
		    ber_scanf(elm, "{se}", &coid, &cval) == -1)
			break;
		DPRINTF("found control %s, cval = %p", coid, cval);
		if (strcmp(oid, coid) == 0) {
			if (ber_scanf(cval, "x", &cbuf, &csiz) == 0) {
				*val = aldap_bermake(cbuf, csiz);
			} else if (val)
				*val = NULL;
			return 0;
		}
	}

	return -1;
}

struct ber_val *
aldap_bermake(void *data, size_t size)
{
	struct ber_val *bv;

	if ((bv = calloc(1, sizeof(*bv))) == NULL)
		return NULL;
	bv->data = data;
	bv->size = size;
	return bv;
}

void
aldap_berfree(struct ber_val *val)
{
	if (val) {
		if (val->root)
			ber_free_elements(val->root);
		free(val);
	}
}

int
aldap_get_page_control(struct aldap_message *msg, int *sizep,
    struct ber_val **cookie)
{
	struct ber		 ber;
	struct ber_val		*cval;
	struct ber_element	*root;
	size_t			 sz;

	if (aldap_get_control(msg, LDAP_CONTROL_PAGED_RESULTS, &cval) == -1 ||
	    cval == NULL)
		return -1;

	DPRINTF("control value has length %zu", cval->size);

	bzero(&ber, sizeof(ber));
	ber_set_application(&ber, aldap_application);
	ber_set_readbuf(&ber, cval->data, cval->size);
	if ((root = ber_read_elements(&ber, NULL)) == NULL)
		return -1;
	LDAP_DEBUG("paged results control value", root);
	cval->root = root;
	if (ber_scanf(root, "{dx}", &sz, &cval->data, &cval->size) == -1) {
		DPRINTF("paged results control value invalid");
		aldap_berfree(cval);
		return -1;
	}

	if (sizep)
		*sizep = sz;

	if (cookie)
		*cookie = cval;
	else
		aldap_berfree(cval);

	return 0;
}

struct ber_element *
aldap_page_control(int critical, int size, struct ber_val *cookie)
{
	struct ber_element	*root = NULL, *cval;
	struct ibuf		*buf;
	void			*cbuf = NULL;
	size_t			 csiz = 0;

	if (cookie) {
		cbuf = cookie->data;
		csiz = cookie->size;
	}

	if ((cval = ber_printf(NULL, "{dx}", size, cbuf, csiz)) == NULL)
		return NULL;

	buf = ber_write_elements(cval);
	ber_free_elements(cval);
	if (buf == NULL)
		return NULL;

	root = ber_printf(NULL, "{sbx}", LDAP_CONTROL_PAGED_RESULTS, critical,
	    buf->buf, ibuf_size(buf));
	ibuf_free(buf);

	return root;
}

int
aldap_start_tls(struct aldap *ld)
{
	struct ber_element	*root;

	root = ber_printf(NULL, "{d{ts}}", ++ld->msgid,
	    BER_CLASS_APP, (unsigned long)LDAP_REQ_EXTENDED,
	    LDAP_EXT_REQ_START_TLS);
	if (root == NULL) {
		ld->err = ALDAP_ERR_OPERATION_FAILED;
		return -1;
	}

	return aldap_enqueue(ld, root);
}

static int
aldap_ssl_check(struct aldap *ld, int ret, const char *where)
{
	switch (SSL_get_error(ld->ssl, ret)) {
	case SSL_ERROR_WANT_READ:
		ld->ssl_ev |= POLLIN;
		break;
	case SSL_ERROR_WANT_WRITE:
		ld->ssl_ev |= POLLOUT;
		break;
	case SSL_ERROR_ZERO_RETURN:
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
	default:
		SSL_DEBUG(where);
		aldap_disconnect(ld);
		return -1;
	}

	return 0;
}

int
aldap_ssl_connect(struct aldap *ld)
{
	int ret;

	DPRINTF("connecting SSL client");
	ret = SSL_connect(ld->ssl);
	if (ret <= 0)
		return aldap_ssl_check(ld, ret, "SSL_connect");
	ld->ssl_connected = 1;
	DPRINTF("SSL connected");
	return 0;
}

int
aldap_ssl_init(struct aldap *ld)
{
	SSL_CTX	*ctx = NULL;

	if (!ssl_initialized) {
		DPRINTF("initializing SSL library");
		SSL_library_init();
		SSL_load_error_strings();
		OpenSSL_add_all_algorithms();

		/* Init hardware crypto engines. */
		ENGINE_load_builtin_engines();
		ENGINE_register_all_complete();

		ssl_initialized = 1;
	}

	DPRINTF("switching to SSL");
	ld->ssl_connected = 0;

	if ((ctx = SSL_CTX_new(SSLv23_method())) == NULL) {
		SSL_DEBUG("SSL_CTX_new");
		return -1;
	}

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_timeout(ctx, SSL_TIMEOUT);
	SSL_CTX_set_options(ctx, SSL_OP_ALL);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

	if (!SSL_CTX_set_cipher_list(ctx, SSL_CIPHERS)) {
		SSL_DEBUG("SSL_CTX_set_cipher_list");
		goto fail;
	}

	if ((ld->ssl = SSL_new(ctx)) == NULL)
		goto fail;
	if (!SSL_set_ssl_method(ld->ssl, SSLv23_client_method()))
		goto fail;
	if (!SSL_set_fd(ld->ssl, ld->fd))
		goto fail;
	SSL_set_connect_state(ld->ssl);
	ld->ssl_ev = POLLOUT;
	return 0;

fail:
	if (ld->ssl)
		SSL_free(ld->ssl);
	else if (ctx)
		SSL_CTX_free(ctx);
	ld->ssl = NULL;
	return -1;
}

int
aldap_ssl_init_s(struct aldap *ld)
{
	if (aldap_ssl_init(ld) == -1)
		return -1;

	do {
		if (aldap_poll(ld, 0, NULL) == -1)
			return -1;
	} while (!ld->ssl_connected);

	return 0;
}

int
aldap_start_tls_s(struct aldap *ld)
{
	int msgid, code;

	if ((msgid = aldap_start_tls(ld)) == -1)
		return -1;
	if ((code = aldap_result(ld, msgid, NULL, NULL)) != LDAP_SUCCESS)
		return code;

	if (aldap_ssl_init_s(ld) == -1)
		return -1;

	return code;
}

static struct aldap_message *
aldap_parse(struct aldap *ld, struct ber_element *root)
{
	struct aldap_message	*msg;

	if ((msg = calloc(1, sizeof(*msg))) == NULL)
		goto fail;

	/* Parse message envelope. */
	if (ber_scanf(root, "{dte{", &msg->msgid, &msg->class, &msg->type,
	    &msg->res) != 0) {
		DPRINTF("failed to parse message envelope");
		goto fail;
	}

	DPRINTF("got response msgid %d, type %lu", msg->msgid, msg->type);
	LDAP_DEBUG("message", root);

	switch (msg->type) {
	case LDAP_RES_BIND:
	case LDAP_RES_MODIFY:
	case LDAP_RES_ADD:
	case LDAP_RES_DELETE:
	case LDAP_RES_MODRDN:
	case LDAP_RES_COMPARE:
	case LDAP_RES_EXTENDED:
	case LDAP_RES_SEARCH_RESULT:
		if (ber_scanf(msg->res, "{Esse}e", &msg->code, &msg->dn,
		    &msg->diagnostic_msg, &msg->optional, &msg->controls) != 0)
			goto fail;

		LDAP_DEBUG("msg->optional", msg->optional);

		if (msg->code == LDAP_REFERRAL)
			if (ber_scanf(msg->optional, "{e}e",
			    &msg->references, &msg->optional) != 0)
				goto fail;
		break;
	case LDAP_RES_SEARCH_ENTRY:
		if (ber_scanf(msg->res, "{s{e}}", &msg->dn, &msg->attributes) != 0)
			goto fail;

		DPRINTF("got search entry '%s'", msg->dn);
		break;
	case LDAP_RES_SEARCH_REFERENCE:
		if (ber_scanf(msg->res, "{e}", &msg->references) != 0)
			goto fail;
		break;
	default:
		DPRINTF("got unhandled message type %lu", msg->type);
		goto fail;
	}

	msg->root = root;
	TAILQ_INSERT_TAIL(&ld->msgq, msg, next);
	return msg;

fail:
	ld->err = ALDAP_ERR_PARSER_ERROR;
	aldap_freemsg(msg);
	ber_free_elements(root);
	return NULL;
}

void
aldap_freemsg(struct aldap_message *msg)
{
	if (msg) {
		if (msg->root)
			ber_free_elements(msg->root);
		free(msg);
	}
}

int
aldap_msgtype(struct aldap_message *msg)
{
	return msg->type;
}

int
aldap_get_resultcode(struct aldap_message *msg)
{
	return msg->code;
}

char *
aldap_get_dn(struct aldap_message *msg)
{
	return msg->dn;
}

char **
aldap_get_references(struct aldap_message *msg)
{
	if (msg->references == NULL)
		return NULL;
	return aldap_get_stringset(msg->references);
}

char *
aldap_get_diagmsg(struct aldap_message *msg)
{
	return msg->diagnostic_msg;
}

const char *
aldap_next_attribute(struct aldap_message *msg, struct ber_element **iter)
{
	char *attrdesc;

	if (msg->type != LDAP_RES_SEARCH_ENTRY) {
		DPRINTF("not a search entry:");
		LDAP_DEBUG("message", msg->root);
		return NULL;
	}

	if (*iter == NULL)
		*iter = msg->attributes;
	else if (*iter == (void *)-1)
		return NULL;

	if (ber_scanf(*iter, "{s(", &attrdesc) != 0)
		return NULL;

	*iter = (*iter)->be_next;
	if (*iter == NULL)
		*iter = (void *)-1;
	return attrdesc;
}

char **
aldap_get_values(struct aldap_message *msg, const char *attrdesc)
{
	struct ber_element	*a, *b = NULL;
	char			*descr = NULL;

	if (msg->type != LDAP_RES_SEARCH_ENTRY)
		return NULL;

	for (a = msg->attributes; a != NULL; a = a->be_next) {
		if (ber_scanf(a, "{s(e", &descr, &b) != 0)
			return NULL;
		if (strcasecmp(descr, attrdesc) == 0)
			return aldap_get_stringset(b);
	}

	return NULL;
}

void
aldap_free_values(char **values)
{
	int i;

	for (i = 0; values != NULL && values[i] != NULL; i++)
		free(values[i]);
	free(values);
}

void
aldap_free_url(struct aldap_url *lu)
{
	free(lu->buffer);
	free(lu->params.filter);
}

static int
xdigit(int c)
{
	c = tolower(c);
	if (c >= 'a')
		return c - 'a' + 10;
	return c - '0';
}

/*
 * Replaces %XX in string with the hexadecimal character code.
 * Modifies the argument.
 */
static void
url_decode(char *s)
{
	char *p;

	for (p = s; *s != '\0'; p++)
		if (*s == '%' && isxdigit(s[1]) && isxdigit(s[2])) {
			*p = (xdigit(s[1]) << 4) + xdigit(s[2]);
			s += 3;
		} else
			*p = *s++;

	*p = '\0';
}

int
aldap_parse_url(char *url, struct aldap_url *lu)
{
	char		*p, *forward, *forward2;
	const char	*errstr = NULL;
	int		 i;

	bzero(&lu->params, sizeof(lu->params));
	if ((lu->buffer = p = strdup(url)) == NULL)
		return (-1);

	/* protocol */
	if ((forward = strchr(p, ':')) == NULL)
		goto fail;
	*forward = '\0';
	if (strcasecmp(p, "ldap") == 0)
		lu->protocol = LDAP;
	else if (strcasecmp(p, "ldaps") == 0)
		lu->protocol = LDAPS;
	else if (strcasecmp(p, "ldapi") == 0)
		lu->protocol = LDAPI;
	else
		goto fail;
	p = ++forward;
	if (p[0] != '/' || p[1] != '/')
		goto fail;
	p += 2;

	/* host and optional port */
	if ((forward = strchr(p, '/')) != NULL)
		*forward = '\0';
	/* find the optional port */
	if ((forward2 = strchr(p, ':')) != NULL) {
		*forward2 = '\0';
		/* if a port is given */
		if (*(forward2+1) != '\0') {
#define PORT_MAX UINT16_MAX
			lu->port = strtonum(++forward2, 0, PORT_MAX, &errstr);
			if (errstr)
				goto fail;
		}
	}
	/* fail if no host is given */
	if (strlen(p) == 0)
		goto fail;
	lu->host = p;
	if (forward == NULL)
		goto done;
	/* p is assigned either a pointer to a character or to '\0' */
	p = ++forward;
	if (strlen(p) == 0)
		goto done;

	/* dn */
	if ((forward = strchr(p, '?')) != NULL)
		*forward = '\0';
	lu->params.basedn = p;
	if (forward == NULL)
		goto done;
	/* p is assigned either a pointer to a character or to '\0' */
	p = ++forward;
	if (strlen(p) == 0)
		goto done;

	/* attributes */
	if ((forward = strchr(p, '?')) != NULL)
		*forward = '\0';
	for (i = 0; i < ALDAP_MAXATTR; i++) {
		if ((forward2 = strchr(p, ',')) == NULL) {
			if (strlen(p) == 0)
				break;
			lu->params.attributes[i] = p;
			break;
		}
		*forward2 = '\0';
		lu->params.attributes[i] = p;
		p = ++forward2;
	}
	if (forward == NULL)
		goto done;
	/* p is assigned either a pointer to a character or to '\0' */
	p = ++forward;
	if (strlen(p) == 0)
		goto done;

	/* scope */
	if ((forward = strchr(p, '?')) != NULL)
		*forward = '\0';
	if (strcmp(p, "base") == 0)
		lu->params.scope = LDAP_SCOPE_BASE;
	else if (strcmp(p, "one") == 0)
		lu->params.scope = LDAP_SCOPE_ONELEVEL;
	else if (strcmp(p, "sub") == 0)
		lu->params.scope = LDAP_SCOPE_SUBTREE;
	else
		goto fail;
	if (forward == NULL)
		goto done;
	p = ++forward;
	if (strlen(p) == 0)
		goto done;

	/* filter */
	if (p)
		lu->params.filter = p;
done:
	url_decode(lu->host);
	return (1);
fail:
	free(lu->buffer);
	lu->buffer = NULL;
	return (-1);
}

int
aldap_search_url(struct aldap *ldap, char *url, int typesonly, int sizelimit,
    int timelimit)
{
	struct aldap_url	*lu;
	int			 msgid = -1;

	if ((lu = calloc(1, sizeof(*lu))) == NULL)
		return (-1);

	if (aldap_parse_url(url, lu) == 0) {
		lu->params.typesonly = typesonly;
		lu->params.sizelimit = sizelimit;
		lu->params.timelimit = timelimit;

		msgid = aldap_search(ldap, &lu->params);
	}

	aldap_free_url(lu);
	return msgid;
}

static char **
aldap_get_stringset(struct ber_element *elm)
{
	struct ber_element *a;
	int i;
	char **ret;
	char *s;

	if (elm->be_type != BER_TYPE_OCTETSTRING)
		return NULL;

	for (a = elm, i = 1; i > 0 && a != NULL && a->be_type ==
	    BER_TYPE_OCTETSTRING; a = a->be_next, i++)
		;
	if (i == 1)
		return NULL;

	if ((ret = calloc(i + 1, sizeof(char *))) == NULL)
		return NULL;

	for (a = elm, i = 0; a != NULL && a->be_type == BER_TYPE_OCTETSTRING;
	    a = a->be_next, i++) {

		ber_get_string(a, &s);
		ret[i] = utoa(s);
	}
	ret[i + 1] = NULL;

	return ret;
}

/*
 * Base case for ldap_do_parse_search_filter
 *
 * returns:
 *	struct ber_element *, ber_element tree
 *	NULL, parse failed
 */
static struct ber_element *
ldap_parse_search_filter(struct ber_element *ber, const char *filter)
{
	struct ber_element *elm;
	const char *cp;

	cp = filter;

	if (cp == NULL || *cp == '\0') {
		errno = EINVAL;
		return (NULL);
	}

	if ((elm = ldap_do_parse_search_filter(ber, &cp)) == NULL)
		return (NULL);

	if (*cp != '\0') {
		ber_free_elements(elm);
		errno = EINVAL;
		return (NULL);
	}

	return (elm);
}

/*
 * Translate RFC4515 search filter string into ber_element tree
 *
 * returns:
 *	struct ber_element *, ber_element tree
 *	NULL, parse failed
 *
 * notes:
 *	when cp is passed to a recursive invocation, it is updated
 *	    to point one character beyond the filter that was passed
 *	    i.e., cp jumps to "(filter)" upon return
 *	                               ^
 *	goto's used to discriminate error-handling based on error type
 *	doesn't handle extended filters (yet)
 *
 */
static struct ber_element *
ldap_do_parse_search_filter(struct ber_element *prev, const char **cpp)
{
	struct ber_element	*elm, *root = NULL;
	const char		*attr_desc, *attr_val, *cp;
	char			*parsed_val;
	size_t			 len;
	unsigned long		 type;

	/* cpp should pass in pointer to opening parenthesis of "(filter)" */
	cp = *cpp;
	if (*cp != '(')
		goto syntaxfail;

	switch (*++cp) {
	case '&':		/* AND */
	case '|':		/* OR */
		if (*cp == '&')
			type = LDAP_FILT_AND;
		else
			type = LDAP_FILT_OR;

		if ((elm = ber_add_set(prev)) == NULL)
			goto callfail;
		root = elm;
		ber_set_header(elm, BER_CLASS_CONTEXT, type);

		if (*++cp != '(')		/* opening `(` of filter */
			goto syntaxfail;

		while (*cp == '(') {
			if ((elm =
			    ldap_do_parse_search_filter(elm, &cp)) == NULL)
				goto bad;
		}

		if (*cp != ')')			/* trailing `)` of filter */
			goto syntaxfail;
		break;

	case '!':		/* NOT */
		if ((root = ber_add_sequence(prev)) == NULL)
			goto callfail;
		ber_set_header(root, BER_CLASS_CONTEXT, LDAP_FILT_NOT);

		cp++;				/* now points to sub-filter */
		if ((elm = ldap_do_parse_search_filter(root, &cp)) == NULL)
			goto bad;

		if (*cp != ')')			/* trailing `)` of filter */
			goto syntaxfail;
		break;

	default:	/* SIMPLE || PRESENCE */
		attr_desc = cp;

		len = strcspn(cp, "()<>~=");
		cp += len;
		switch (*cp) {
		case '~':
			type = LDAP_FILT_APPR;
			cp++;
			break;
		case '<':
			type = LDAP_FILT_LE;
			cp++;
			break;
		case '>':
			type = LDAP_FILT_GE;
			cp++;
			break;
		case '=':
			type = LDAP_FILT_EQ;	/* assume EQ until disproven */
			break;
		case '(':
		case ')':
		default:
			goto syntaxfail;
		}
		attr_val = ++cp;

		/* presence filter */
		if (strncmp(attr_val, "*)", 2) == 0) {
			cp++;			/* point to trailing `)` */
			if ((root =
			    ber_add_nstring(prev, attr_desc, len)) == NULL)
				goto bad;

			ber_set_header(root, BER_CLASS_CONTEXT, LDAP_FILT_PRES);
			break;
		}

		if ((root = ber_add_sequence(prev)) == NULL)
			goto callfail;
		ber_set_header(root, BER_CLASS_CONTEXT, type);

		if ((elm = ber_add_nstring(root, attr_desc, len)) == NULL)
			goto callfail;

		len = strcspn(attr_val, "*)");
		if (len == 0 && *cp != '*')
			goto syntaxfail;
		cp += len;
		if (*cp == '\0')
			goto syntaxfail;

		if (*cp == '*') {	/* substring filter */
			int initial;

			cp = attr_val;

			ber_set_header(root, BER_CLASS_CONTEXT, LDAP_FILT_SUBS);

			if ((elm = ber_add_sequence(elm)) == NULL)
				goto callfail;

			for (initial = 1;; cp++, initial = 0) {
				attr_val = cp;

				len = strcspn(attr_val, "*)");
				if (len == 0) {
					if (*cp == ')')
						break;
					else
						continue;
				}
				cp += len;
				if (*cp == '\0')
					goto syntaxfail;

				if (initial)
					type = LDAP_FILT_SUBS_INIT;
				else if (*cp == ')')
					type = LDAP_FILT_SUBS_FIN;
				else
					type = LDAP_FILT_SUBS_ANY;

				if ((parsed_val = parseval(attr_val, len)) ==
				    NULL)
					goto callfail;
				elm = ber_add_nstring(elm, parsed_val,
				    strlen(parsed_val));
				free(parsed_val);
				if (elm == NULL)
					goto callfail;
				ber_set_header(elm, BER_CLASS_CONTEXT, type);
				if (type == LDAP_FILT_SUBS_FIN)
					break;
			}
			break;
		}

		if ((parsed_val = parseval(attr_val, len)) == NULL)
			goto callfail;
		elm = ber_add_nstring(elm, parsed_val, strlen(parsed_val));
		free(parsed_val);
		if (elm == NULL)
			goto callfail;
		break;
	}

	cp++;		/* now points one char beyond the trailing `)` */

	*cpp = cp;
	return (root);

syntaxfail:		/* XXX -- error reporting */
callfail:
bad:
	if (root != NULL)
		ber_free_elements(root);
	ber_link_elements(prev, NULL);
	return (NULL);
}

#ifdef DEBUG
/*
 * Display a list of ber elements.
 *
 */
void
ldap_debug_elements(struct ber_element *root)
{
	static int	 indent = 0;
	long long	 v;
	int		 d;
	char		*buf, *visbuf;
	size_t		 len;
	u_int		 i;
	int		 constructed;
	struct ber_oid	 o;

	/* calculate lengths */
	ber_calc_len(root);

	switch (root->be_encoding) {
	case BER_TYPE_SEQUENCE:
	case BER_TYPE_SET:
		constructed = root->be_encoding;
		break;
	default:
		constructed = 0;
		break;
	}

	fprintf(stderr, "%*slen %lu ", indent, "", root->be_len);
	switch (root->be_class) {
	case BER_CLASS_UNIVERSAL:
		fprintf(stderr, "class: universal(%u) type: ", root->be_class);
		switch (root->be_type) {
		case BER_TYPE_EOC:
			fprintf(stderr, "end-of-content");
			break;
		case BER_TYPE_BOOLEAN:
			fprintf(stderr, "boolean");
			break;
		case BER_TYPE_INTEGER:
			fprintf(stderr, "integer");
			break;
		case BER_TYPE_BITSTRING:
			fprintf(stderr, "bit-string");
			break;
		case BER_TYPE_OCTETSTRING:
			fprintf(stderr, "octet-string");
			break;
		case BER_TYPE_NULL:
			fprintf(stderr, "null");
			break;
		case BER_TYPE_OBJECT:
			fprintf(stderr, "object");
			break;
		case BER_TYPE_ENUMERATED:
			fprintf(stderr, "enumerated");
			break;
		case BER_TYPE_SEQUENCE:
			fprintf(stderr, "sequence");
			break;
		case BER_TYPE_SET:
			fprintf(stderr, "set");
			break;
		}
		break;
	case BER_CLASS_APPLICATION:
		fprintf(stderr, "class: application(%u) type: ",
		    root->be_class);
		switch (root->be_type) {
		case LDAP_REQ_BIND:
			fprintf(stderr, "bind");
			break;
		case LDAP_RES_BIND:
			fprintf(stderr, "bind");
			break;
		case LDAP_REQ_UNBIND_30:
			break;
		case LDAP_REQ_SEARCH:
			fprintf(stderr, "search");
			break;
		case LDAP_RES_SEARCH_ENTRY:
			fprintf(stderr, "search_entry");
			break;
		case LDAP_RES_SEARCH_RESULT:
			fprintf(stderr, "search_result");
			break;
		case LDAP_REQ_MODIFY:
			fprintf(stderr, "modify");
			break;
		case LDAP_RES_MODIFY:
			fprintf(stderr, "modify");
			break;
		case LDAP_REQ_ADD:
			fprintf(stderr, "add");
			break;
		case LDAP_RES_ADD:
			fprintf(stderr, "add");
			break;
		case LDAP_REQ_DELETE_30:
			fprintf(stderr, "delete");
			break;
		case LDAP_RES_DELETE:
			fprintf(stderr, "delete");
			break;
		case LDAP_REQ_MODRDN:
			fprintf(stderr, "modrdn");
			break;
		case LDAP_RES_MODRDN:
			fprintf(stderr, "modrdn");
			break;
		case LDAP_REQ_COMPARE:
			fprintf(stderr, "compare");
			break;
		case LDAP_RES_COMPARE:
			fprintf(stderr, "compare");
			break;
		case LDAP_REQ_ABANDON_30:
			fprintf(stderr, "abandon");
			break;
		}
		break;
	case BER_CLASS_PRIVATE:
		fprintf(stderr, "class: private(%u) type: ", root->be_class);
		fprintf(stderr, "encoding (%lu) type: ", root->be_encoding);
		break;
	case BER_CLASS_CONTEXT:
		/* XXX: this is not correct */
		fprintf(stderr, "class: context(%u) type: ", root->be_class);
		switch(root->be_type) {
		case LDAP_AUTH_SIMPLE:
			fprintf(stderr, "auth simple");
			break;
		}
		break;
	default:
		fprintf(stderr, "class: <INVALID>(%u) type: ", root->be_class);
		break;
	}
	fprintf(stderr, "(%lu) encoding %lu ",
	    root->be_type, root->be_encoding);

	if (constructed)
		root->be_encoding = constructed;

	switch (root->be_encoding) {
	case BER_TYPE_BOOLEAN:
		if (ber_get_boolean(root, &d) == -1) {
			fprintf(stderr, "<INVALID>\n");
			break;
		}
		fprintf(stderr, "%s(%d)\n", d ? "true" : "false", d);
		break;
	case BER_TYPE_INTEGER:
		if (ber_get_integer(root, &v) == -1) {
			fprintf(stderr, "<INVALID>\n");
			break;
		}
		fprintf(stderr, "value %lld\n", v);
		break;
	case BER_TYPE_ENUMERATED:
		if (ber_get_enumerated(root, &v) == -1) {
			fprintf(stderr, "<INVALID>\n");
			break;
		}
		fprintf(stderr, "value %lld\n", v);
		break;
	case BER_TYPE_BITSTRING:
		if (ber_get_bitstring(root, (void *)&buf, &len) == -1) {
			fprintf(stderr, "<INVALID>\n");
			break;
		}
		fprintf(stderr, "hexdump ");
		for (i = 0; i < len; i++)
			fprintf(stderr, "%02x", buf[i]);
		fprintf(stderr, "\n");
		break;
	case BER_TYPE_OBJECT:
		if (ber_get_oid(root, &o) == -1) {
			fprintf(stderr, "<INVALID>\n");
			break;
		}
		fprintf(stderr, "\n");
		break;
	case BER_TYPE_OCTETSTRING:
		if (ber_get_nstring(root, (void *)&buf, &len) == -1) {
			fprintf(stderr, "<INVALID>\n");
			break;
		}
		if ((visbuf = malloc(len * 4 + 1)) != NULL) {
			strvisx(visbuf, buf, len, 0);
			fprintf(stderr, "string \"%s\"\n",  visbuf);
			free(visbuf);
		}
		break;
	case BER_TYPE_NULL:	/* no payload */
	case BER_TYPE_EOC:
	case BER_TYPE_SEQUENCE:
	case BER_TYPE_SET:
	default:
		fprintf(stderr, "\n");
		break;
	}

	if (constructed && root->be_sub) {
		indent += 2;
		ldap_debug_elements(root->be_sub);
		indent -= 2;
	}
	if (root->be_next)
		ldap_debug_elements(root->be_next);
}
#endif

/*
 * Convert UTF-8 to ASCII.
 * notes:
 *	non-ASCII characters are displayed as '?'
 *	the argument u should be a NULL terminated sequence of UTF-8 bytes.
 */
static char *
utoa(char *u)
{
	int	 len, i, j;
	char	*str;

	/* calculate the length to allocate */
	for (len = 0, i = 0; u[i] != '\0'; ) {
		if ((u[i] & 0xF0) == 0xF0)
			i += 4;
		else if ((u[i] & 0xE0) == 0xE0)
			i += 3;
		else if ((u[i] & 0xC0) == 0xC0)
			i += 2;
		else
			i += 1;
		len++;
	}

	if ((str = calloc(len + 1, sizeof(char))) == NULL)
		return NULL;

	/* copy the ASCII characters to the newly allocated string */
	for (i = 0, j = 0; u[i] != '\0'; j++) {
		if ((u[i] & 0xF0) == 0xF0) {
			str[j] = '?';
			i += 4;
		} else if ((u[i] & 0xE0) == 0xE0) {
			str[j] = '?';
			i += 3;
		} else if ((u[i] & 0xC0) == 0xC0) {
			str[j] = '?';
			i += 2;
		} else {
			str[j] =  u[i];
			i += 1;
		}
	}

	return str;
}

/*
 * Parse a LDAP value
 * notes:
 *	the argument u should be a NULL terminated sequence of ASCII bytes.
 */
static char *
parseval(const char *p, size_t len)
{
	char		 hex[3];
	const char	*cp = p;
	char		*buffer, *newbuffer;
	size_t		 size, newsize, i, j;

	size = 50;
	if ((buffer = calloc(1, size)) == NULL)
		return NULL;

	for (i = j = 0; j < len; i++) {
		if (i >= size) {
			newsize = size + 1024;
			if ((newbuffer = realloc(buffer, newsize)) == NULL) {
				free(buffer);
				return (NULL);
			}
			buffer = newbuffer;
			size = newsize;
		}

		if (cp[j] == '\\') {
			strlcpy(hex, cp + j + 1, sizeof(hex));
			buffer[i] = (char)strtoumax(hex, NULL, 16);
			j += 3;
		} else {
			buffer[i] = cp[j];
			j++;
		}
	}

	return buffer;
}

int
aldap_get_errno(struct aldap *a, const char **estr)
{
	switch (a->err) {
	case ALDAP_ERR_SUCCESS:
		*estr = "success";
		break;
	case ALDAP_ERR_PARSER_ERROR:
		*estr = "parser failed";
		break;
	case ALDAP_ERR_INVALID_FILTER:
		*estr = "invalid filter";
		break;
	case ALDAP_ERR_OPERATION_FAILED:
		*estr = "operation failed";
		break;
	case ALDAP_ERR_CONNECTION_CLOSED:
		*estr = "connection closed";
		break;
	default:
		*estr = "unknown";
		break;
	}
	return (a->err);
}

char *
aldap_strerror(int err)
{
	static struct {
		int	 code;
		char	*str;
	} errors[] = {
		{ LDAP_SUCCESS,			"Success" },
		{ LDAP_OPERATIONS_ERROR,	"Operations error" },
		{ LDAP_PROTOCOL_ERROR,		"Protocol error" },
		{ LDAP_TIMELIMIT_EXCEEDED,	"Time limit exceeded" },
		{ LDAP_SIZELIMIT_EXCEEDED,	"Size limit exceeded" },
		{ LDAP_COMPARE_FALSE,		"False" },
		{ LDAP_COMPARE_TRUE,		"True" },
		{ LDAP_STRONG_AUTH_NOT_SUPPORTED, "Strong authentication not supported" },
		{ LDAP_STRONG_AUTH_REQUIRED,	"Strong authentication required" },

		{ LDAP_REFERRAL,		"Referral" },
		{ LDAP_ADMINLIMIT_EXCEEDED,	"Admin limit exceeded" },
		{ LDAP_UNAVAILABLE_CRITICAL_EXTENSION, "Unavailable critical extension" },
		{ LDAP_CONFIDENTIALITY_REQUIRED, "Confidentiality required" },
		{ LDAP_SASL_BIND_IN_PROGRESS,	"SALS bind in progress" },
		{ LDAP_NO_SUCH_ATTRIBUTE,	"No such attribute" },
		{ LDAP_UNDEFINED_TYPE,		"Undefined type" },
		{ LDAP_INAPPROPRIATE_MATCHING,	"Inappropriate matching" },
		{ LDAP_CONSTRAINT_VIOLATION,	"Constraint violation" },
		{ LDAP_TYPE_OR_VALUE_EXISTS,	"Type of value exists" },
		{ LDAP_INVALID_SYNTAX,		"Invalid syntax" },

		{ LDAP_NO_SUCH_OBJECT,		"No such object" },
		{ LDAP_ALIAS_PROBLEM,		"Alias problem" },
		{ LDAP_INVALID_DN_SYNTAX,	"Invalid DN syntax" },

		{ LDAP_ALIAS_DEREF_PROBLEM,	"Alias dereference problem" },

		{ LDAP_INAPPROPRIATE_AUTH,	"Inappropriate authentication" },
		{ LDAP_INVALID_CREDENTIALS,	"Invalid credentials" },
		{ LDAP_INSUFFICIENT_ACCESS,	"Insufficient access" },
		{ LDAP_BUSY,			"Busy" },
		{ LDAP_UNAVAILABLE,		"Unavailable" },
		{ LDAP_UNWILLING_TO_PERFORM,	"Unwilling to perform" },
		{ LDAP_LOOP_DETECT,		"Loop detected" },

		{ LDAP_NAMING_VIOLATION	,	"Naming violation" },
		{ LDAP_OBJECT_CLASS_VIOLATION,	"Object class violation" },
		{ LDAP_NOT_ALLOWED_ON_NONLEAF,	"Operation not allowed on nonleaf" },
		{ LDAP_NOT_ALLOWED_ON_RDN,	"Operation not allowed on RDN" },
		{ LDAP_ALREADY_EXISTS,		"Already exists" },
		{ LDAP_NO_OBJECT_CLASS_MODS,	"No object class modifications" },

		{ LDAP_AFFECTS_MULTIPLE_DSAS,	"Affects multiple DSAs" },

		{ LDAP_OTHER,			"Other error" }
	};
	unsigned int	 i;
	unsigned int	 nitems = sizeof(errors) / sizeof(errors[0]);

	if (err == -1)
		return strerror(errno);

	for (i = 0; i < nitems; i++)
		if (errors[i].code == err)
			return errors[i].str;
	return "Unknown error";
}

