# OTR version 4 library

[![Build Status](https://travis-ci.org/otrv4/libotrv4.svg?branch=master)](https://travis-ci.org/otrv4/libotrv4)


## Build
Before you try to build libotrv4, verify you have installed:
* autoconf - https://www.gnu.org/software/autoconf/autoconf.html
* splint - http://splint.org/documentation
* valgrind - http://valgrind.org/. At least, version 3.12.0

Then, install the following dependencies:
* libglib2.0-dev
* libdecaf
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

To configure project with code-coverage option:

Install:
* lcov
* genhtml

```
$ ./configure --enable-code-coverage
```
