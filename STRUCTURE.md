# Structure

This document describe shortly how the code base is structured in order to make
it nice and easy to use this library as a library, and also provide for good
unit testing capabilities.

## Header files

There are two places to put header files. The files in `src` will only be
available during build time of libotr-ng. If you have API functionality that you
want to expose, it should instead be put in `src/include`.

It's important that all header files have "header guards" - the format for that
is established in the existing files.

## Export levels

There are three levels of export that is possible inside the libotr-ng project:
local, internal and API.

1. Local

Local functions must be marked with tstatic. These functions should also be
placed in the PRIVATE segment of the corresponding header file - this makes it
possible for tests to access the functionality when needed.

2. Internal

Functions that will be used by other compilation units in libotr-ng, but not
outside of libotr-ng, should be marked with the INTERNAL marker on both
declaration and definition.

3. API

Finally, functions that are to be exposed as API functions should be marked with
the API marker on both declaration and definition. They should also be put
inside header files in the `src/include` directory, not inside src.

Structures and other dependent things also need to be moved to the API header
files, if they are exposed, if they are arguments or return
values of API functions, or if they are members of other structs that are API
structs.

## Naming

For any cases where naming needs to be done in a way to avoid name clashes, the
name should be prefixed with `otrng_` or `OTRNG_` depending on the kind of thing
that is exposed.

For items that have to do with the version 3 functionality, the prefix should be
`otrng_v3_`.

Local functions can have any name - since they will not clash. However, internal
and API functions always have to be prefixed to avoid name clashes. This is
because even though the names might not be exposed in header files, linking will
fail if two functions with the same name exists in any compilation unit.

For exposed structs, API naming rules apply - but for all other structs, there
is no risk of name clashes, so any name can be used.
