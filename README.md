# OTR version 4 library
![Travis](https://travis-ci.org/twstrike/libotr.svg?branch=master)

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
$ ./configure --disable-shared
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
