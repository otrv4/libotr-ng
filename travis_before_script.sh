#!/usr/bin/env bash

set -xe

mkdir -p .deps

# OK, so there's some weirdness in this file. Basically, this weirdness is for a few reasons:
# - we want to use the cache of Travis if possible. If things are cached we don't want to recompile.
# - sudo make install can sometimes fail due to travis not making clang available to sudo
#   - so, we use -E and -i. However, -i moves to root homedirectory, so we need to switch back
#   - but doing that on one command line with sudo in bash is not fantastic. easier to have a
#     separate helper script so that we can do this. however, since the helper script is in the
#     source distribution we also need to keep track of the current directory, and use absolute
#     paths for those things
# - all of this horribleness would probably be easier solved by rejigging everything to install
#   in a local lib/include directory, but that caused conflicts with system installed things
#   sometimes, so it would need more investigation and work to make it functional.

GPG_ERROR_DIR=.deps/libgpg-error-1.26
LIBSODIUM_DIR=.deps/libsodium-stable
CTGRIND_DIR=.deps/ctgrind
VALGRIND_DIR=.deps/valgrind-3.13.0
LIBOTR_DIR=.deps/libotr
LIBGOLDILOCKS_DIR=.deps/libgoldilocks
SOURCE_DIR=`pwd`
MAKE_INSTALL="sudo -E -i $SOURCE_DIR/run_make_install.sh"

echo `which clang`

if [[ $TRAVIS_OS_NAME == 'linux' ]]; then

    if [[ -f $GPG_ERROR_DIR/src/.libs/libgpg-error.so ]]; then
        $MAKE_INSTALL $SOURCE_DIR/$GPG_ERROR_DIR
    else
        curl https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.26.tar.bz2 | tar xjf - -C .deps
        (cd $GPG_ERROR_DIR && ./configure && make -j && $MAKE_INSTALL $SOURCE_DIR/$GPG_ERROR_DIR)
    fi

    if [[ -f $LIBSODIUM_DIR/src/libsodium/.libs/libsodium.so ]]; then
        $MAKE_INSTALL $SOURCE_DIR/$LIBSODIUM_DIR
    else
        curl https://download.libsodium.org/libsodium/releases/LATEST.tar.gz | tar xzf - -C .deps
        (cd $LIBSODIUM_DIR && ./autogen.sh && ./configure && make -j && $MAKE_INSTALL $SOURCE_DIR/$LIBSODIUM_DIR)
    fi
fi
if [[ "$T" = "ctgrind" ]]; then
    if [[ -f $CTGRIND_DIR/memcheck/vgpreload_memcheck-amd64-linux.so ]]; then
        $MAKE_INSTALL $SOURCE_DIR/$CTGRIND_DIR
    else
        rm -rf $CTGRIND_DIR
        git clone --depth=1 https://github.com/claucece/ctgrind $CTGRIND_DIR
        (cd $CTGRIND_DIR && ./autogen.sh && ./configure && make -j && $MAKE_INSTALL $SOURCE_DIR/$CTGRIND_DIR)
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
(cd $LIBOTR_DIR && ./bootstrap && ./configure && make -j && $MAKE_INSTALL $SOURCE_DIR/$LIBOTR_DIR)
# fi

if [[ -f $LIBGOLDILOCKS_DIR/src/.libs/libgoldilocks.so ]]; then
    $MAKE_INSTALL $SOURCE_DIR/$LIBGOLDILOCKS_DIR
else
    rm -rf $LIBGOLDILOCKS_DIR
    git clone --depth=1 https://github.com/otrv4/libgoldilocks $LIBGOLDILOCKS_DIR
    (cd $LIBGOLDILOCKS_DIR && ./autogen.sh && ./configure && make -j && $MAKE_INSTALL $SOURCE_DIR/$LIBGOLDILOCKS_DIR)
fi
