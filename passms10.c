/* gcc -m64 -Os -W -Wall -Werror -fomit-frame-pointer -mno-sse -c passms.c && objdump -d passms.o */

/* Trampoline function to call a System V amd64 ABI function (fs) from a
 * Windows amd64 ABI function.
 */
__attribute__((ms_abi)) long passms10(long a, long b, long c, long d, long e, long f, long g, long h, long i, long j,
                                      long (*fs)(long a, long b, long c, long d, long e, long f, long g, long h, long i, long j)) {
  return fs(a, b, c, d, e, f, g, h, i, j);
}

/*
https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions
http://msdn.microsoft.com/en-us/library/ew5tede7(v=VS.90).aspx

Windows incoming stack (8 bytes each): <return-address> <shadow1> <shadow2> <shadow3> <shadow4> <arg5> <arg6> <arg7> <arg8> <arg9> <arg10> <function>
Incoming registers: rcx=<arg1> rdx=<arg2> r8=<arg3> r9=<arg4>
Callee must preserve (nonvolatile): RBX, RBP, RDI, RSI, R12, R13, R14, R15 
Callee can clobber (scratch, volatile): RAX, RCX, RDX, R8, R9, R10, R11
Return value up to 64 bits in RAX.

System V outgoing stack: <return-address2> <arg7> <arg8> <arg9> <arg10>
Outgoing registers: rdi=<arg1> rsi=<arg2> rdx=<arg3> rcx=<arg4> r8=<arg5> r9=<arg6>
Callee must preserve (nonvolatile): RBX, RBP, R12, R13, R14, R15
Callee can clobber (scratch, volatile): RAX, RCX, RDX, RDI, RSI, R8, R9, R10, R11
Return value up to 64 bits in RAX, 65..128 bits in RDX:RAX.

Difference: These are scratch in System V only: RDI, RSI.

*/
