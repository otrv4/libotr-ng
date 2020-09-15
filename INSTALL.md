# How to install the library

In order to install the library, you will need:

* libglib2.0-dev
* libgcrypt 1.8.0 or newer
* libgoldilocks
* libsodium-dev
* libotr 4.x

This can be installed in different ways depending on the OS.

## Installing dependencies for Linux systems

You can install the dependencies in the following way:

- You will need to first install libgpg:
  - `curl https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.26.tar.bz2 | tar xjf -`
  - `cd $libgpg-error-1.26`
  - `./configure`
  - `make && make install`
- `sudo apt-get install libgcrypt20-dev`
- `sudo apt-get install libglib2.0-dev`
- Install libsodium:
  - `curl https://download.libsodium.org/libsodium/releases/LATEST.tar.gz | tar xzf -`
  - `cd libsodium-stable`
  - `./autogen.sh && ./configure`
  - `make && make install`
- Install libotr:
  - `git clone --depth=1 https://bugs.otr.im/lib/libotr.git`
  - `cd libotr`
  - `./bootstrap && ./configure`
  -  `make && make install`
- Install libgoldilocks:
  - `git clone --depth=1 https://bugs.otr.im/otrv4/libgoldilocks`
  - `cd libgoldilocks`
  - `./autogen.sh && ./configure`
  - `make && make install`

## Installing dependencies for OSX systems

You can install the dependencies in the following way:

- You will need to first install libgpg:
  - `curl https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.26.tar.bz2 | tar xjf -`
  - `cd $libgpg-error-1.26`
  - `./configure`
  - `make && make install`
- `brew install curl && brew install glib`
- `brew install libgcrypt`
- `brew install libsodium`
- Install libotr:
  - `git clone --depth=1 https://bugs.otr.im/lib/libotr.git`
  - `cd libotr`
  - `./bootstrap && ./configure`
  -  `make && make install`
- Install libgoldilocks:
  - `git clone --depth=1 https://bugs.otr.im/otrv4/libgoldilocks`
  - `cd libgoldilocks`
  - `./autogen.sh && ./configure`
  - `make && make install`

## Installing the library on Linux

You will need to execute:

- `export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}`
- `export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH}"`
- `./autogen.sh`
- `./configure`
- `make && make install`

## Installing the library on OSX

You will need to execute:

- `./autogen.sh`
- `./configure`
- `make && make install`

