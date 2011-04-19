.PATH:          ${.CURDIR}/..

PROG=		ldapsearch
NOMAN=		
SRCS=		ldapadd.c ldif.c ber.c aldap.c

LDADD=		-lutil -lssl -lcrypto
DPADD=		${LIBEVENT} ${LIBCRYPTO} ${LIBZ} ${LIBUTIL}
CFLAGS+=	-g
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare

.include <bsd.prog.mk>
