/*
 * Reads authorized_keys lines, one hex-encoded line per input line, and prints how
 * OpenSSH's own functions read each of them, in the order sshd's authorized_keys loop
 * calls them before it compares any key: skip blank and comment lines, read a key, or
 * step over an options field and read the key after it, then parse the options.
 *
 * Output, one line per input line, tab separated:
 *   BLANK
 *   REJECT <stage>                       stage: quote, key or options
 *   ACCEPT <name> <short> <bits> <sha256> <md5> <comment-hex> <options...>
 * where <options...> are key=value pairs with hex values (- for none).
 */
#include "includes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sshkey.h"
#include "authfile.h"
#include "auth-options.h"
#include "digest.h"
#include "misc.h"
#include "ssherr.h"

void
cleanup_exit(int code)
{
	_exit(code);
}

/* sshkey.c links against the signing helpers; reading keys never calls them. */
int sshsk_sign(void) { return -1; }
int pkcs11_sign(void) { return -1; }
void pkcs11_key_free(void) { }

static int
nibble(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static void
put_hex(const char *s)
{
	if (s == NULL) {
		fputs("-", stdout);
		return;
	}
	if (*s == '\0')
		fputs("=", stdout);
	for (; *s != '\0'; s++)
		printf("%02x", (unsigned char)*s);
}

static void
put_list(const char *label, char **items, size_t n)
{
	size_t i;

	printf("\t%s=", label);
	if (n == 0)
		fputs("-", stdout);
	for (i = 0; i < n; i++) {
		if (i > 0)
			fputs(",", stdout);
		put_hex(items[i]);
	}
}

static void
report(struct sshkey *key, const char *comment, struct sshauthopt *o)
{
	char *sha = sshkey_fingerprint(key, SSH_DIGEST_SHA256, SSH_FP_DEFAULT);
	char *md5 = sshkey_fingerprint(key, SSH_DIGEST_MD5, SSH_FP_DEFAULT);

	printf("ACCEPT\t%s\t%s\t%u\t%s\t%s\t", sshkey_ssh_name(key),
	    sshkey_type(key), sshkey_size(key), sha, md5);
	put_hex(comment);
	printf("\trestricted=%d\tport=%d\tagent=%d\tx11=%d\tpty=%d\tuserrc=%d",
	    o->restricted, o->permit_port_forwarding_flag,
	    o->permit_agent_forwarding_flag, o->permit_x11_forwarding_flag,
	    o->permit_pty_flag, o->permit_user_rc);
	printf("\tcertauth=%d\tnotouch=%d\tverify=%d\ttun=%d\texpiry=%llu",
	    o->cert_authority, o->no_require_user_presence, o->require_verify,
	    o->force_tun_device, (unsigned long long)o->valid_before);
	fputs("\tcommand=", stdout);
	put_hex(o->force_command);
	fputs("\tprincipals=", stdout);
	put_hex(o->cert_principals);
	fputs("\tfrom=", stdout);
	put_hex(o->required_from_host_keys);
	put_list("env", o->env, o->nenv);
	put_list("permitopen", o->permitopen, o->npermitopen);
	put_list("permitlisten", o->permitlisten, o->npermitlisten);
	fputs("\n", stdout);
	free(sha);
	free(md5);
}

static void
check_line(char *line)
{
	char *cp = line, *key_options = NULL;
	const char *reason = NULL;
	struct sshkey *found;
	struct sshauthopt *opts;

	skip_space(&cp);
	if (!*cp || *cp == '\n' || *cp == '#') {
		puts("BLANK");
		return;
	}
	if ((found = sshkey_new(KEY_UNSPEC)) == NULL)
		cleanup_exit(3);
	if (sshkey_read(found, &cp) != 0) {
		key_options = cp;
		if (sshkey_advance_past_options(&cp) != 0) {
			puts("REJECT\tquote");
			sshkey_free(found);
			return;
		}
		skip_space(&cp);
		if (sshkey_read(found, &cp) != 0) {
			puts("REJECT\tkey");
			sshkey_free(found);
			return;
		}
	}
	if ((opts = sshauthopt_parse(key_options, &reason)) == NULL) {
		puts("REJECT\toptions");
		sshkey_free(found);
		return;
	}
	/* The comment runs to the end of the line, newline excluded. */
	cp[strcspn(cp, "\n")] = '\0';
	report(found, cp, opts);
	sshauthopt_free(opts);
	sshkey_free(found);
}

int
main(void)
{
	char *in = NULL, *line;
	size_t cap = 0, i, n;
	ssize_t got;
	int hi, lo;

	while ((got = getline(&in, &cap, stdin)) != -1) {
		while (got > 0 && (in[got - 1] == '\n' || in[got - 1] == '\r'))
			got--;
		n = (size_t)got / 2;
		/* sshd reads lines with their newline, so one is put back. */
		if ((line = malloc(n + 2)) == NULL)
			cleanup_exit(3);
		for (i = 0; i < n; i++) {
			hi = nibble(in[2 * i]);
			lo = nibble(in[2 * i + 1]);
			if (hi < 0 || lo < 0)
				cleanup_exit(2);
			line[i] = (char)(hi << 4 | lo);
		}
		line[n] = '\n';
		line[n + 1] = '\0';
		check_line(line);
		free(line);
		fflush(stdout);
	}
	free(in);
	return 0;
}
