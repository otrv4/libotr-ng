# OTR version 4 library

[![Build Status](https://travis-ci.org/twstrike/libotrv4.svg?branch=master)](https://travis-ci.org/twstrike/libotrv4)

## Build
Before you try to build libotrv4 verify you have installed
* autoconf - https://www.gnu.org/software/autoconf/autoconf.html
* splint - http://splint.org/documentation
* valgrind - http://valgrind.org/

Then you should install the following dependencies
* libglib2.0-dev
* libdecaf
* libsodium-dev
* libcramershoup
* libgcrypt

Generate project configuration
```
$ autoreconf --install
```

Configure project
```
$ ./configure
```

Configure project with debug options
```
$ ./configure CFLAGS="-g -ggdb3 -O0" CXXFLAGS="-g -ggdb3 -O0" LDFLAGS="-g -ggdb3" --disable-shared
$ gdb [path/test/executable]
```

Build and install
```
$ make && make install
```

Run tests
```
$ make test
```
