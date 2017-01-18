#!/bin/sh

set -e

# TODO "autoreconf --install" seems to be enough. But it requires autotools >= 1.6

case "$(uname)" in
    Darwin)
        LIBTOOLIZE=${LIBTOOLIZE:-glibtoolize}
        ;;
    *)
        LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}
        ;;
esac

aclocal -I m4 && \
  ${LIBTOOLIZE} --automake --copy && \
  autoconf && \
  autoheader && \
  automake --add-missing --copy

