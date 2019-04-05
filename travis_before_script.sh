#!/usr/bin/env bash

set -xe

mkdir -p .deps

GPG_ERROR_DIR=.deps/libgpg-error-1.26
LIBGCRYPT_DIR=.deps/libgcrypt-1.8.1
LIBSODIUM_DIR=.deps/libsodium-stable
CTGRIND_DIR=.deps/ctgrind
VALGRIND_DIR=.deps/valgrind-3.13.0
LIBOTR_DIR=.deps/libotr
LIBGOLDILOCKS_DIR=.deps/libgoldilocks

echo `which clang`

if [[ $TRAVIS_OS_NAME == 'linux' ]]; then
    if [[ -f $GPG_ERROR_DIR/src/.libs/libgpg-error.so ]]; then
        (cd $GPG_ERROR_DIR && sudo -E -i (cd $GPG_ERROR_DIR && make install))
    else
        curl https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.26.tar.bz2 | tar xjf - -C .deps
        (cd $GPG_ERROR_DIR && ./configure && make -j && sudo -E -i (cd $GPG_ERROR_DIR && make install))
    fi

    # if [[ -f $LIBGCRYPT_DIR/src/.libs/libgcrypt.so ]]; then
    #     (cd $LIBGCRYPT_DIR && sudo make install)
    # else
    curl https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.1.tar.bz2 | tar xjf - -C .deps
    (cd $LIBGCRYPT_DIR && ./configure && make -j && sudo -i make install)
    # fi

    if [[ -f $LIBSODIUM_DIR/src/libsodium/.libs/libsodium.so ]]; then
        (cd $LIBSODIUM_DIR && sudo -i make install)
    else
        curl https://download.libsodium.org/libsodium/releases/LATEST.tar.gz | tar xzf - -C .deps
        (cd $LIBSODIUM_DIR && ./autogen.sh && ./configure && make -j && sudo -i make install)
    fi
fi
if [[ "$T" = "ctgrind" ]]; then
    if [[ -f $CTGRIND_DIR/memcheck/vgpreload_memcheck-amd64-linux.so ]]; then
        (cd $CTGRIND_DIR && sudo -i make install)
    else
        rm -rf $CTGRIND_DIR
        git clone --depth=1 https://github.com/claucece/ctgrind $CTGRIND_DIR
        (cd $CTGRIND_DIR && ./autogen.sh && ./configure && make -j && sudo -i make install)
    fi
fi

if [[ $TRAVIS_OS_NAME == 'osx' ]]; then
    curl https://sourceware.org/ftp/valgrind/valgrind-3.13.0.tar.bz2 | tar xjf - -C .deps
    (cd $VALGRIND_DIR && ./configure && make -j && make install)
fi

# if [[ -f $LIBOTR_DIR/src/.libs/libotr.so ]]; then
#     (cd $LIBOTR_DIR && sudo make install)
# else
if [[ ! -e $LIBOTR_DIR ]]; then
    git clone --depth=1 https://bugs.otr.im/lib/libotr.git $LIBOTR_DIR
fi
(cd $LIBOTR_DIR && ./bootstrap && ./configure && make -j && sudo -i make install)
# fi

if [[ -f $LIBGOLDILOCKS_DIR/src/.libs/libgoldilocks.so ]]; then
    (cd $LIBGOLDILOCKS_DIR && sudo -i make install)
else
    rm -rf $LIBGOLDILOCKS_DIR
    git clone --depth=1 https://github.com/otrv4/libgoldilocks $LIBGOLDILOCKS_DIR
    (cd $LIBGOLDILOCKS_DIR && ./autogen.sh && ./configure && make -j && sudo -i make install)
fi
