/*	$Id: ldapadd.c,v 1.7 2011-01-11 18:02:13 martinh Exp $ */

/*
 * Copyright (c) 2011 Martin Hedenfalk <martinh@openbsd.org>
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aldap.h"
#include "ldif.h"

static void
usage(void)
{
	extern const char *__progname;
	printf("%s [-xWZ] [-h host] [-p port] [-D binddn] [-w passwd] [-f file]\n",
	    __progname);
}

static int
process_ldif(struct aldap *ld, FILE *fp)
{
	struct ber_element	*elm, *root;
	int			 code = 0, lineno = 0;
	unsigned long long	 n = 0;

	fprintf(stderr, "reading ldif\n");

	while ((elm = ldif_parse_file(fp, &lineno)) != NULL) {
		root = ber_printf(NULL, "{de}", ++ld->msgid, elm);
		if (root == NULL)
			goto fail;
		elm = NULL;
		if (aldap_enqueue(ld, root) == -1)
			goto fail;
		code = aldap_result(ld, ld->msgid, NULL, NULL);
		fprintf(stderr, "got return code %i\n", code);
		if (code != 0)
			break;
		++n;
	}

	if (code == 0)
		fprintf(stderr, "loaded %llu entries\n", n);
	else
		fprintf(stderr, "%s\n", aldap_strerror(code));

	if (fp != stdin)
		fclose(fp);
	return code;

fail:
	if (fp != stdin)
		fclose(fp);
	if (root)
		ber_free_elements(root);
	if (elm)
		ber_free_elements(elm);
	return 1;
}

int
main(int argc, char **argv)
{
	struct aldap_url	 url;
	char			*hostname = NULL;
	const char		*binddn = NULL, *passwd = NULL;
	const char		*errmsg = NULL;
	struct aldap		*ld;
	FILE			*fp = NULL;
	int			 c, port = 0, starttls = 1, ret;

	bzero(&url, sizeof(url));

	while ((c = getopt(argc, argv, "Cf:h:H:p:D:ZvWw:x")) != -1) {
		switch (c) {
		case 'f':
			if (fp != NULL)
				err(1, "-f already specified");
			if (strcmp(optarg, "-") == 0)
				fp = stdin;
			else if ((fp = fopen(optarg, "r")) == NULL)
				err(1, optarg);
			break;
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
			if (port == 0 && url.protocol == LDAPS)
				port = 636;
			break;
		case 'p':
			port = strtonum(optarg, 1, 65535, &errmsg);
			if (errmsg != NULL)
				errx(1, "port is %s", errmsg);
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
		case 'v':
			break;
		case 'w':
			passwd = optarg;
			break;
		case 'W':
		case 'x':
			break;
		default:
			usage();
			return 1;
		}
	}

	argc -= optind;
	argv += optind;

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

	if (fp == NULL)
		fp = stdin;

	process_ldif(ld, fp);
	aldap_unbind_s(ld);

	if (fp != stdin)
		fclose(fp);

	return 0;
}

