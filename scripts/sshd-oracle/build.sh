#!/bin/sh
# Build the sshd oracle: OpenSSH's own authorized_keys reading code (sshkey_read,
# sshkey_advance_past_options, sshauthopt_parse) behind harness.c, from the pinned
# openssh-portable commit. Needs a C compiler, make, autoconf and the OpenSSL and zlib
# development headers. Extra include or library folders go in CPPFLAGS and LDFLAGS.
#
#   sh scripts/sshd-oracle/build.sh <work folder>
#   AUTHKEYLINE_SSHD_HARNESS=<work folder>/harness pytest tests/test_sshd_oracle.py
set -eu
COMMIT=773771be4ae241380e5f2b65059c441f7eef2da7
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mkdir -p "$1" && cd "$1" && pwd)
SRC=$WORK/openssh-portable-$COMMIT
if [ ! -d "$SRC" ]; then
    curl -fsSL "https://github.com/openssh/openssh-portable/archive/$COMMIT.tar.gz" \
        | tar -xz -C "$WORK"
fi
cd "$SRC"
[ -f configure ] || autoreconf
[ -f config.h ] || ./configure --without-pam --without-selinux --without-kerberos5 \
    --without-libedit > "$WORK/configure.log"
make -j4 libssh.a openbsd-compat/libopenbsd-compat.a > "$WORK/make.log"
cc -O1 -I. -Iopenbsd-compat ${CPPFLAGS:-} -DHAVE_CONFIG_H -o "$WORK/harness" \
    "$HERE/harness.c" auth-options.c libssh.a openbsd-compat/libopenbsd-compat.a libssh.a \
    ${LDFLAGS:-} -lcrypto -lz -lcrypt -lresolv
"$WORK/harness" < /dev/null
echo "built $WORK/harness"
