# Style

// TODO: check clang.format

Based on: [LinuxKernelCodingStyle](http://www.maultech.com/chrislott/resources/cstyle/LinuxKernelCodingStyle.txt)

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
