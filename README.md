# OTR Next Generation library

[![Build Status](https://travis-ci.org/otrv4/libotr-ng.svg?branch=master)](https://travis-ci.org/otrv4/libotr-ng)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fotrv4%2Flibotr-ng.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fotrv4%2Flibotr-ng?ref=badge_shield)
[![Coverity Status](https://scan.coverity.com/projects/16830/badge.svg)](https://scan.coverity.com/projects/libotr-ng)


## Build

Before you try to build libotr-ng, verify you have installed:
* autoconf - https://www.gnu.org/software/autoconf/autoconf.html
* splint - http://splint.org/documentation
* valgrind - http://valgrind.org/. At least, version 3.12.0

Then, install the following dependencies:
* libglib2.0-dev
* libgcrypt 1.8.0 or newer
* libgoldilocks
* libsodium-dev
* libotr 4.x

To generate project configuration:

```
$ autoreconf --install
```

To configure the project:

```
$ ./configure
```

To build and install:

```
$ make && make install
```

To run the tests:

```
$ make test
```

## Configure library with other options

To configure the project with OTRNG debug output:

```
./configure CFLAGS="-ggdb3 -O0 -D DEBUG_API=yes"
```

To configure the project with debug option using `gdb`:
```
$ ./configure CFLAGS="-g -ggdb3 -O0" CXXFLAGS="-g -ggdb3 -O0" LDFLAGS="-g -ggdb3" --disable-shared
$ gdb [path/test/executable]
```

To configure project with debug option using `lldb`:
```
$ ./configure CFLAGS="-g -ggdb3 -O0" CXXFLAGS="-g -ggdb3 -O0" LDFLAGS="-g -ggdb3" --disable-shared
$ lldb [path/test/executable]
```

To configure project with debug option:
```
$ ./configure --enable-debug
```

To run `make code-style`:


Install:
* clang-format-3.5


## Usage

This library is primarily meant to be used by instance messaging clients to provide OTRv4 encryption on top of the library. The main entry points for the functionality can be found in client.h - the functions `otrng_client_receive` and `otrng_client_send` can be used as starting points for investigation of the functionality.


### Thread safety

The `libotr-ng` library is not inherently thread safe. Since the library is meant to be used in widely different environments with different threading libraries and process requirements, it would be impossible for the library itself to use a specific thread safety paradigm. Thus, the client application will have to ensure this.

Almost all functions in this library are safe in the sense that they only modify structures and memory that has been explicitly sent in as arguments to the functions. There is no global state in the system, with the exception of the out-of-memory handler. This means that it is possible to concurrently call functions as long as they don't modify the same memory area. However, for large chunks of the OTR functionality, the functions will touch on central areas relating to lists of clients.

The limit of interaction between OTR functions is guided by the `otrng_global_state_s` structure - for client instances that are part of different global states, it is completely safe to call functions concurrently.

In terms of how to ensure thread safety, the easiest way would be to make sure there's always a lock around calls to OTR functionality, so that only one call from a client to the library can happen at the same time. Another way would be to always serialize calls using a message queue or something along those lines. Another way would be - like in Pidgin - to not have multipled threads at all. However you choose to do it, it's important to ensure this thread safety, since the results of not doing it are unpredictable and potentially very dangerous.


## License

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fotrv4%2Flibotr-ng.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fotrv4%2Flibotr-ng?ref=badge_large)
