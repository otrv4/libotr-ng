# Style

For formatting the code, please use:

```
make code-style
```

This style is based on:

* [LinuxKernelCodingStyle](http://www.maultech.com/chrislott/resources/cstyle/LinuxKernelCodingStyle.txt)
* [llvm coding standars](https://llvm.org/docs/CodingStandards.html)
* [GNU Coding Standars](https://www.gnu.org/prep/standards/standards.html)

## Formatting

Keep the length of source lines to 79 characters or less, for maximum
readability.

## Tabs and Spaces

In all cases, prefer spaces to tabs. The current indent width is 2.

Follow the Golden Rule: follow the style of existing code if you are modifying
and extending it.

## Naming

C is a Spartan language, and so should your naming be.  C programmers do
not use cute names like ThisVariableIsATemporaryCounter.  A C programmer
would call that variable "tmp", which is much easier to write, and not the
least more difficult to understand.

GLOBAL variables (to be used only if you _really_ need them) need to
have descriptive names, as do global functions.  If you have a function
that counts the number of active users, you should call that
"count_active_users()" or similar, you should _not_ call it "cntusr()".

If you are afraid to mix up your local variable names, you have another
problem, which is called the function-growth-hormone-imbalance syndrome.

Use underscores to separate words in a name instead of camel case.
Stick to lower case; reserve uppercase for macros.

## Language and compiler issues

* Treat compiler warnings as errors.
* #include as little as possible.
