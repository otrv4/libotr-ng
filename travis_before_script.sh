#!/usr/bin/env bash

set -ex

mkdir -p .deps

GPG_ERROR_DIR=.deps/libgpg-error-1.26
LIBGCRYPT_DIR=.deps/libgcrypt-1.8.1
LIBSODIUM_DIR=.deps/libsodium-stable
CTGRIND_DIR=.deps/ctgrind
LIBOTR_DIR=.deps/libotr
LIBGOLDILOCKS_DIR=.deps/libgoldilocks

if [[ $TRAVIS_OS_NAME == 'linux' ]]; then
    if [[ -f $GPG_ERROR_DIR/src/.libs/libgpg-error.so ]]; then
        pushd $GPG_ERROR_DIR && sudo make install && popd
    else
        curl https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.26.tar.bz2 | tar xjf - -C .deps
        pushd $GPG_ERROR_DIR && ./configure && make && sudo make install&& popd
    fi

    if [[ -f $LIBGCRYPT_DIR/src/.libs/libgcrypt.so ]]; then
        pushd $LIBGCRYPT_DIR && sudo make install && popd
    else
        curl https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.1.tar.bz2 | tar xjf - -C .deps
        pushd $LIBGCRYPT_DIR && ./configure && make && sudo make install && popd
    fi
    if [[ -f $LIBSODIUM_DIR/src/libsodium/.libs/libsodium.so ]]; then
        pushd $LIBSODIUM_DIR && sudo make install && popd
    else
        curl https://download.libsodium.org/libsodium/releases/LATEST.tar.gz | tar xzf - -C .deps
        pushd $LIBSODIUM_DIR && ./autogen.sh && ./configure && make && sudo make install && popd
    fi
fi
if [[ "$T" = "ctgrind" ]]; then
    if [[ -f $CTGRIND_DIR/memcheck/vgpreload_memcheck-amd64-linux.so ]]; then
        pushd $CTGRIND_DIR && sudo make install && popd
    else
        git clone --depth=1 https://github.com/claucece/ctgrind $CTGRIND_DIR
        pushd $CTGRIND_DIR && ./autogen.sh && ./configure && make && sudo make install && popd
    fi
fi

if [[ -f $LIBOTR_DIR/src/.libs/libotr.so ]]; then
    pushd $LIBOTR_DIR && sudo make install && popd
else
    git clone --depth=1 https://bugs.otr.im/lib/libotr.git $LIBOTR_DIR
    pushd $LIBOTR_DIR && ./bootstrap && ./configure && make && sudo make install && popd
fi

if [[ -f $LIBGOLDILOCKS_DIR/src/.libs/libgoldilocks.so ]]; then
    pushd $LIBGOLDILOCKS_DIR && sudo make install && popd
else
    git clone --depth=1 https://github.com/otrv4/libgoldilocks $LIBGOLDILOCKS_DIR
    pushd $LIBGOLDILOCKS_DIR && ./autogen.sh && ./configure && make && sudo make install && popd
fi
