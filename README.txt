pynativeload: load and call native code from Python
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
pynativeload can load native code (precompiled, architecture-dependent machine
code) to a Python process and call it. It's similar to C extensions, but it
has different tradeoffs (e.g. platform-independent, doesn't separate files),
and it's more suitable for bundling a small amount of performance-critical
native code to single-file Python scripts.

Suggested use case: Do the performance-critical algorithmic heavy lifting in
native code (loaded by pynativeload), and do everything else in Python code.
Example for performance-critical code for which pynativeload is a good fit:
encryption and compression of large amounts of data.

Status: pynativeload is under development, it's not stable or ready
for general use. The source code repository is provided as is, best effort.

Features:

* platform-independent code: pynativeload can load code precompiled with gcc
  for Linux on most major platforms (e.g. Linux, macOS, Windows, FreeBSD),
  there is no need to build the code for multiple platforms.
* Python-only: pynativeload itself is pure Python code, and it uses the
  ctypes or dl standard module to run native code. It doesn't have any
  other dependencies (e.g. specific libc, Python development libraries).
* backwards-compatible: pynativeload is compatible with Python 2.4 ... 3.8
  (and possible others in the future). (Python 2.4 doesn't have ctypes by
  default. If a specific installation doesn't have dl either, then install
  ctypes from PyPI.)
* any-file: pynativeload can load code from any file, including code embedded
  in the .py script itself.

Limitations:

* relative jumps and calls: Works only on architectures where jumps, calls
  and branches are relative. (This includes x86 32-bit and 64-bit and arm
  32-bit and 64-bit, but it excludes e.g. mips.)
* no global variables: Doesn't support code with global variables or
  constants (e.g. C "string" literals).
* no libary dependencies: Doesn't support code with external library
  dependencies (e.g. -lz for zlib).
* no Python dependencies: Native code can't call Python code.
* no Python C API dependencies: Doesn't support code calling the Python C
  API (e.g. PyInt_AsLong).
* no libc dependencies: Doesn't support code with libc function dependencies
  (e.g. printf, memcpy).
* maximum 10 arguments per function call.
* no floating point arguments or return values (but pointers to them are
  fine).
* no functions with variable number of arguments.
* return value size: Size of a function return value can be up to 64 bits
  (on x86 and amd64), 128-bit values don't work (but pointers to them are
  fine).

__END__
