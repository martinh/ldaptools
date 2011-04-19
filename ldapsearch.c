/*	$Id: ldapsearch.c,v 1.2 2011-01-11 08:58:10 martinh Exp $ */

/*
 * Copyright (c) 2010 Martin Hedenfalk <martinh@openbsd.org>
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
#include <netinet/in.h>

#include <err.h>
#include <limits.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aldap.h"

static void
usage(void)
{
	extern const char *__progname;
	printf("%s [-xCWZ] [-h host] [-p port] [-H ldapurl] [-D binddn] [-w passwd]\n",
	    __progname);
	printf("     [-b basedn] [-s scope] [-l timelimit] [-z sizelimit] [-P pagesize]\n");
}

/* FIXME: obviously we need a length too to handle non-c-strings */
static int
ldif_need_encoding(const char *value)
{
	static const char *unsafe_init_chars = "\r\n :<";
	static const char *unsafe_chars = "\r\n";

	if (*value == '\0')	/* zero-length attribute value */
		return 0;

	if (strchr(unsafe_init_chars, *value) != NULL)
		return 1;

	for (++value; *value != '\0'; value++)
		if (strchr(unsafe_chars, *value) != NULL)
			return 1;

	return 0;
}

static void
ldif_print_folded(const char *attr, const char *value, int encoded, FILE *fp)
{
	int len;

	len = fprintf(fp, "%s:%s ", attr, encoded ? ":" : "");
	for (; *value != '\0'; value++) {
		if (len % 78 == 0) {
			fprintf(fp, "\n ");
			len++;
		}
		len += fprintf(fp, "%c", *value);
	}
	fprintf(fp, "\n");
}

static void
ldif_print_value(const char *attr, const char *value, FILE *fp)
{
	char	*enc;
	size_t	 sz, encsz;

	if (ldif_need_encoding(value)) {
		sz = strlen(value);
		encsz = (sz * 4) / 3 + 4;
		if ((enc = malloc(encsz)) == NULL)
			err(4, "malloc");
		if (b64_ntop(value, sz, enc, encsz) == -1)
			err(4, "base64 encode");
		ldif_print_folded(attr, enc, 1, fp);
		free(enc);
	} else
		ldif_print_folded(attr, value, 0, fp);
}

static void
ldif_print(struct aldap_message *msg, FILE *fp)
{
	struct ber_element	*elm;
	const char		*attr;
	char			**values, **val;

	ldif_print_value("dn", msg->dn, fp);

	elm = NULL;
	while ((attr = aldap_next_attribute(msg, &elm)) != NULL) {
		values = aldap_get_values(msg, attr);
		for (val = values; val != NULL && *val != NULL; val++)
			ldif_print_value(attr, *val, fp);
		aldap_free_values(values);
	}
	fprintf(fp, "\n");
}

int
main(int argc, char **argv)
{
	struct aldap_url	 url;
	struct aldap_search	 params;
	char			*hostname = NULL;
	const char		*binddn = NULL, *passwd = NULL;
	struct aldap		*ld;
	struct aldap_message	*res;
	struct ber_val		*cookie = NULL;
	const char		*errmsg;
	char			**values, **val;
	int			 c, port = 0, starttls = 1, ret, i;
	int			 msgid, code, pagesize = 1000;

	bzero(&url, sizeof(url));
	bzero(&params, sizeof(params));
	params.scope = 42;	/* auto-detect: base for root DSE, subtree otherwise */

	while ((c = getopt(argc, argv, "h:CH:p:P:D:WZvw:b:s:l:z:x")) != -1) {
		switch (c) {
		case 'h':
			hostname = optarg;
			break;
		case 'H':
			aldap_free_url(&url);
			bzero(&url, sizeof(url));
			if (aldap_parse_url(optarg, &url) == -1)
				errx(2, "invalid LDAP URL: %s", optarg);
			hostname = url.host;
			port = url.port;
			params.basedn = url.params.basedn;
			params.filter = url.params.filter;
			params.scope = url.params.scope;
			bcopy(&url.params.attributes, &params.attributes,
			    sizeof(params.attributes));
			if (port == 0 && url.protocol == LDAPS)
				port = 636;
			break;
		case 'p':
			port = strtonum(optarg, 1, 65535, &errmsg);
			if (errmsg != NULL)
				errx(1, "port is %s", errmsg);
			break;
		case 'P':
			pagesize = strtonum(optarg, 0, INT_MAX, &errmsg);
			if (errmsg != NULL)
				errx(1, "page size is %s", errmsg);
			break;
		case 'D':
			binddn = optarg;
			break;
		case 'C':
			starttls = 0;
			break;
		case 'Z':
			starttls = 2;
			break;
		case 'w':
			passwd = optarg;
			break;
		case 'l':
			if (strcasecmp(optarg, "none") == 0)
				params.timelimit = 0;
			else if (strcasecmp(optarg, "max") == 0)
				params.timelimit = INT_MAX;
			else {
				params.timelimit = strtonum(optarg, 0, INT_MAX, &errmsg);
				if (errmsg != NULL)
					errx(1, "time limit is %s", errmsg);
			}
			break;
		case 'z':
			if (strcasecmp(optarg, "none") == 0)
				params.sizelimit = 0;
			else if (strcasecmp(optarg, "max") == 0)
				params.sizelimit = INT_MAX;
			else {
				params.sizelimit = strtonum(optarg, 0, INT_MAX, &errmsg);
				if (errmsg != NULL)
					errx(1, "size limit is %s", errmsg);
			}
			break;
		case 'W':
		case 'x':
			break;
		case 'b':
			params.basedn = optarg;
			break;
		case 's':
			if (strcmp(optarg, "base") == 0)
				params.scope = LDAP_SCOPE_BASE;
			else if (strcmp(optarg, "one") == 0)
				params.scope = LDAP_SCOPE_ONELEVEL;
			else if (strcmp(optarg, "sub") == 0)
				params.scope = LDAP_SCOPE_SUBTREE;
			break;
		default:
			usage();
			return 1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0) {
		if (strchr(argv[0], '=') != NULL) {
			/* looks like a search filter */
			params.filter = argv[0];
			argc -= 1;
			argv += 1;
		}
	}

	if (params.basedn == NULL)
		params.basedn = "";

	if (params.scope == 42) {
		if (*params.basedn == '\0')
			params.scope = LDAP_SCOPE_BASE;
		else
			params.scope = LDAP_SCOPE_SUBTREE;
	}

	if (argc > 0) {
		for (i = 0; i < argc && i < ALDAP_MAXATTR; i++)
			params.attributes[i] = argv[i];
	}

	if (hostname == NULL) {
		/* default to unix socket /var/run/ldapi */
		url.protocol = LDAPI;
		hostname = "/var/run/ldapi";
		/* errx(1, "missing hostname"); */
	}

	if (binddn != NULL && passwd == NULL) {
		char *prompt;
		if (asprintf(&prompt, "password for %s: ", binddn) == -1)
			err(2, "asprintf");
		if ((passwd = getpass(prompt)) == NULL)
			return 3;
		free(prompt);
	}

	if (url.protocol == LDAPI)
		ld = aldap_open_local(hostname);
	else
		ld = aldap_open(hostname, port);
	if (ld == NULL)
		err(2, "%s", hostname);

	if (url.protocol == LDAPS) {
		if (aldap_ssl_init_s(ld) == -1)
			err(3, "ssl");
	} else if (((url.protocol == LDAPI && starttls == 2) ||
	     (url.protocol == LDAP && starttls)) &&
	    (ret = aldap_start_tls_s(ld)) != 0) {
		if (starttls == 2)	/* starttls required */
			err(2, "%s: %s", hostname, aldap_strerror(ret));
	}

	if (binddn && (ret = aldap_bind_s(ld, binddn, passwd)) != 0)
		errx(2, "failed to bind: %s", aldap_strerror(ret));

	printf("version: 1\n\n");

	for (;;) {
		if (pagesize > 0) {
			params.controls[0] =
			    aldap_page_control(0, pagesize, cookie);
			if (params.controls[0] == NULL)
				err(2, "failed to create paged results control");
			aldap_berfree(cookie);
		}

		if ((msgid = aldap_search(ld, &params)) == -1) {
			aldap_get_errno(ld, &errmsg);
			errx(1, "search failed: %s", errmsg);
		}

		for (;;) {
			code = aldap_result(ld, msgid, NULL, &res);
			if (code == -1) {
				aldap_get_errno(ld, &errmsg);
				errx(1, "search failed: %s", errmsg);
			}

			if (aldap_msgtype(res) == LDAP_RES_SEARCH_RESULT)
				break;
			if (aldap_msgtype(res) == LDAP_RES_SEARCH_REFERENCE) {
				aldap_freemsg(res);
				continue;
			}

			ldif_print(res, stdout);
			aldap_freemsg(res);
		}

		if (code == LDAP_REFERRAL) {
			values = aldap_get_references(res);
			for (val = values; val != NULL && *val != NULL; val++)
				printf("referral: %s\n", *val);
			aldap_free_values(values);
			break;
		}

		if (aldap_get_page_control(res, NULL, &cookie) == -1)
			break;
		aldap_freemsg(res);

		if (cookie->size == 0) {	/* last page */
			aldap_berfree(cookie);
			break;
		}

#if 0
		fprintf(stderr, "press enter for next page\n");
		getchar();
#endif
	}

	aldap_unbind_s(ld);

	return 0;
}

