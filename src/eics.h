#include "config.h"
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define MINPASSLEN 8

int eics_get_cb (const char *query, char *pass, int maxlen);
int eics_get_compare_cb (char **p1, char **p2, int maxlen);
int eics_pass_cb (char *pass, int maxlen, int rwflag, void *u);
