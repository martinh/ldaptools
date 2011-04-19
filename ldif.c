/*	$Id: ldif.c,v 1.5 2011-01-11 18:02:29 martinh Exp $ */

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
#include <errno.h>
#include <resolv.h>		/* for b64_pton */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ldif.h"
#include "aldap.h"

#ifdef DEBUG
# define DPRINTF(...)	do { fprintf(stderr, "%s:%d: ", __func__, __LINE__); \
			     fprintf(stderr, __VA_ARGS__); \
			     fprintf(stderr, "\n"); } while(0)
#else
# define DPRINTF(...)
#endif

/* FIXME: implement support for :< file:// syntax
 */

/* Parses one logical line of LDIF data. The line should not include any line
 * termination characters (CR LF / LF).
 *
 * Returns 0 on success (continue parsing), -1 on error (sets errno)
 * and 1 if the entry is complete.
 *
 * Allocates a BER struct in *root suitable for an LDAP add request.
 */
static int
ldif_parse_line(struct ber_element **root, const char *line)
{
	struct ber_element	*elm = NULL, *seq, *vals;
	char			*key = NULL, *val = NULL, *attr;
	size_t			 n;
	int			 url = 0, base64_decode = 0, sz;

	if (root == NULL || line == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (*line == '\0') {
		if (*root == NULL)
			return 0;	/* Skip leading empty lines. */
		return 1;		/* An empty line delimits entries. */
	}

	if (*line == '#')		/* Skip comments. */
		return 0;

	DPRINTF("parsing line [%s]", line);

	n = strcspn(line, ":");
	if (line[n] != ':')
		goto fail;
	if ((key = strndup(line, n)) == NULL)
		return -1;
	line += n + 1;

	if (*line == ':') {
		base64_decode = 1;	/* key:: base64 encoded data */
		line++;
	} else if (*line == '<') {	/* key:< file:///url */
		url = 1;
		line++;
	} else if (*line == '\0')
		goto fail;
	line += strspn(line, " ");

	if (base64_decode) {
		sz = strlen(line) + 1;
		if ((val = malloc(sz)) == NULL)
			goto fail;
		if ((sz = b64_pton(line, val, sz)) == -1)
			goto einval;
		val[sz] = '\0';
	} else if (url) {
		errno = ENOTSUP;
		goto fail;
	} else if ((val = strdup(line)) == NULL)
		goto fail;

	DPRINTF("[%s] = [%s]", key, val);

	if (strcasecmp(key, "version") == 0) {
		if (strcmp(val, "1") != 0)
			goto einval;
	} else if (strcasecmp(key, "dn") == 0) {
		if (*root != NULL) {
			DPRINTF("DN already stored");
			goto einval;
		}

		DPRINTF("adding DN [%s]", val);
		*root = ber_printf(NULL, "{ts",
		    BER_CLASS_APP, (unsigned long)LDAP_REQ_ADD, val);
		if (*root == NULL)
			goto fail;
	} else if (*root == NULL) {
		DPRINTF("entry must begin with DN");
		goto einval;
	} else {
		if (ber_scanf(*root, "{Se", &seq) != 0) {
			DPRINTF("failed to scan root");
			goto einval;
		}

		if (seq == NULL) {
			if ((seq = ber_printf(*root, "{")) == NULL)
				goto einval;
		} else
			for (elm = seq->be_sub; elm; elm = elm->be_next) {
				if (ber_scanf(elm, "{s(e)}", &attr, &vals) != 0)
					goto einval;
				if (strcasecmp(attr, key) == 0)
					break;
			}

		if (elm) {
			if (ber_printf(vals, "s", val) == NULL)
				goto einval;
		} else {
			if ((*root = ber_printf(*root, "{s(s)}", key, val)) == NULL)
				goto einval;
		}
	}

	return 0;

einval:
	DPRINTF("invalid syntax");
	errno = EINVAL;
fail:
	free(key);
	free(val);
	if (elm != NULL)
		ber_free_elements(elm);
	return -1;
}

#if 0
struct ber_element *
ldif_parse_buf(const char *buf, size_t len)
{
	return NULL;
}

struct ber_element *
ldif_parse_str(const char *str)
{
	return ldif_parse_buf(str, strlen(str));
}
#endif

/*
 * Parses one LDIF entry from the file and returns a BER struct suitable
 * for an LDAP request. Returns NULL on error.
 */
struct ber_element *
ldif_parse_file(FILE *fp, int *lineno)
{
	struct ber_element	*root = NULL;
	char			*buf, *lbuf = NULL, *line = NULL, *tmp;
	size_t			 len, llen = 0;
	int			 rc = 1, free_line = 0;

	while ((buf = fgetln(fp, &len))) {
		if (lineno != NULL)
			++*lineno;
		if (buf[len - 1] == '\n') {
			buf[len - 1] = '\0';
			if (len >= 2 && buf[len - 2] == '\r')
				buf[len - 2] = '\0';
		} else {
			/* EOF without EOL, copy and add the NUL */
			if ((lbuf = malloc(len + 1)) == NULL)
				err(1, NULL);
			bcopy(buf, lbuf, len);
			lbuf[len] = '\0';
			buf = lbuf;
		}

		DPRINTF("read line [%s]/%zu", buf, len);

		if (*buf == '\0' && root != NULL)
			break;

		if (buf[0] == ' ') {
			/* line continuation, append to logical line */
			if (line == NULL) {
				DPRINTF("invalid line continuation");
				return NULL;
			}
			DPRINTF("appending [%s]/%zu to line [%s]/%zu",
			    buf + 1, len, line, llen);
			llen += len;
			if (free_line) {
				if ((tmp = realloc(line, llen)) == NULL) {
					DPRINTF("realloc: %s", strerror(errno));
					return NULL;
				}
			} else {
				if ((tmp = malloc(llen)) == NULL) {
					DPRINTF("malloc: %s", strerror(errno));
					return NULL;
				}
				strlcpy(tmp, line, llen);
			}
			line = tmp;
			if (strlcat(line, buf + 1, llen) >= llen) {
				DPRINTF("line truncated");
				return NULL;
			}
			DPRINTF("line is now [%s]/%zu", line, llen);
		} else {
			if (line != NULL)
				if ((rc = ldif_parse_line(&root, line)) != 0)
					break;
			if (free_line)
				free(line);
			line = strdup(buf);
			llen = len;
			free_line = 1;
		}
	}

	if (line != NULL)
		rc = ldif_parse_line(&root, line);
	if (free_line)
		free(line);

	free(lbuf);

	if (rc == -1) {
		if (lineno == NULL)
			DPRINTF("LDIF error");
		else
			DPRINTF("LDIF error at line %d", *lineno);
		if (root != NULL) {
			ber_free_elements(root);
			root = NULL;
		}
	}

	return root;
}

