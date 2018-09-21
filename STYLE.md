# Style

## Basic Rules

- Always code critique each commit and give public comments on it
- Check that the CI is passing on all allowed machines when you push to the repo

## Git and Github

This is a collaborative library, so if you are part of the core OTR
development sign your commits using gpg.

### Commit messages

Good commit messages serve three important purposes:

1. Speed up the reviewing process.
2. Help write a good release note.
3. Help the future maintainers.

Remember to always commit early and to never change published history.

Remember that your commit message should be consistent:

- The first line should be 50 chars long
- Spell check the commit message
- Mention the issue you are working on
- Use active voice and imperative present tense
- Mention who you are working with in the commit message, e.g., +@username
- Don't end the summary line with a period

Structure your commit message like this (taken from
[Distributed Git - Contributing to a Project](#https://git-scm.com/book/en/v2/Distributed-Git-Contributing-to-a-Project):

```
Short (50 chars or less) summary of changes

More detailed explanatory text, if necessary.  Wrap it to about 72
characters or so.  In some contexts, the first line is treated as the
subject of an email and the rest of the text as the body.  The blank
line separating the summary from the body is critical (unless you omit
the body entirely); tools like rebase can get confused if you run the
two together.

Further paragraphs come after blank lines.

  - Bullet points are okay, too

  - Typically a hyphen or asterisk is used for the bullet, preceded by a
    single space, with blank lines in between, but conventions vary here
```

The summary should look like:

```
+@username Summary #issue_number
```

**Note**

Do as we say, not as we do.

## C Style

For formatting the code, please use:

```
make code-style
```

Remember to always prioritize correctness, readability, simplicity and
maintainability over speed because [premature optimization](http://wiki.c2.com/?PrematureOptimization)
is the root of all evil.

This style is based on:

* [LinuxKernelCodingStyle](http://www.maultech.com/chrislott/resources/cstyle/LinuxKernelCodingStyle.txt)
* [llvm coding standars](https://llvm.org/docs/CodingStandards.html)
* [GNU Coding Standars](https://www.gnu.org/prep/standards/standards.html)

### Malloc and Free

Every time you assign memory to a pointer variable, you should free it.
Consider nullifying the variable afterwards, if it can be access afterwards by
something else.

### Golden Rules

Follow these golden rules (taken from [C Style](https://github.com/mcinglis/c-style):

- Follow the style of C99
- Follow the style of existing code if you are modifying and extending it.
- Always develop and compile with all warnings (and more) on
- Never have more than 79 characters per line
- No global or static variables if you can help it (you probably can)
- Immutability saves lives: use `const` everywhere you can
- Be consistent in your variable names across functions
- Use underscores instead of camel case for naming.
- Do not use 'is' or 'has' on booleans naming.
- Minimize the scope of variables
- C isn't object-oriented, and you shouldn't pretend it is
- Set a pointer to NULL after been freed when needed
- Always use parentheses

### Naming

C is a Spartan language, and so should your naming be.  C programmers do not use
cute names like ThisVariableIsATemporaryCounter. A C programmer would call that
variable "tmp", which is much easier to write, and not the least more difficult
to understand.

GLOBAL variables (to be used only if you _really_ need them) need to have
descriptive names, as do global functions.  If you have a function that counts
the number of active users, you should call that "count_active_users()" or
similar, you should _not_ call it "cntusr()".

If you are afraid to mix up your local variable names, you have another problem,
which is called the function-growth-hormone-imbalance syndrome.

Use underscores to separate words in a name instead of camel case.

Stick to lower case; reserve uppercase for macros.

### Language and compiler issues

* Always compile with all the flags we have defined
* Treat compiler warnings as errors
* #include as little as possible

## Development tips

### Compiling for debugging

Run `configure with --enable-debug` to add additional compiler flags.

### Compiling for gprof profiling

Run `configure with the --enable-gprof` option, then `make profile`.

### Compiling for test coverage

LCOV can be used to generate a test coverage report. LCOV must be installed on
your system.

Run `configure with the --enable-lcov` option, then `make profile`.
To enable LCOV report generation during test, run:

```
./configure --enable-lcov
make coverage-check
```

# A coverage report will now be accessible at `./test_bitcoin.coverage/index.html`.
