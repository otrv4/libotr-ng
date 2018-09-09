# OTR Next Generation library

[![Build Status](https://travis-ci.org/otrv4/libotr-ng.svg?branch=master)](https://travis-ci.org/otrv4/libotr-ng)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fotrv4%2Flibotr-ng.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fotrv4%2Flibotr-ng?ref=badge_shield)

## Build
Before you try to build libotr-ng, verify you have installed:
* autoconf - https://www.gnu.org/software/autoconf/autoconf.html
* splint - http://splint.org/documentation
* valgrind - http://valgrind.org/. At least, version 3.12.0

Then, install the following dependencies:
* libglib2.0-dev
* libgoldilocks
* libsodium-dev
* libotr 4.x
* libgcrypt 1.8.0 or newer

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




## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fotrv4%2Flibotr-ng.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fotrv4%2Flibotr-ng?ref=badge_large)