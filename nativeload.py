#! /usr/bin/python
# by pts@fazekas.hu at Sat Dec 14 14:07:10 CET 2019
# !! Make this work in Python 3 with ctypes.

import itertools
import struct
import sys


def addmul(a, b, c, d, e, f, g, h, i):
  r = a * b + c * d + e * f + g * h + i
  return (r & 0x7fffffff) - (r & 0x80000000)  # Sign-extend.


# i386 (32-bit) only code, `import dl' doesn't support 64-bit.
# See compar,nasm for source code.
# It is a smaller version of this C code in the i386 System V ABI:
# struct args {
#   int (*p)(int c, int d, int e, int f, int g, int h, int i, int j, int k, int l);
#   int r[10];
# };
# int compar(struct args *a, struct args *b) {
#   int result = -1;
#   if ((int)a->p == -1) {
#     a = b;
#     result = 1;
#   }
#   if (a->p) {
#     a->r[0] = a->p(a->r[0], a->r[1], a->r[2], a->r[3], a->r[4], a->r[5], a->r[6], a->r[7], a->r[8], a->r[9]);
#     a->p = 0;
#   }
#   return result;
# }
_compar_code = '56578B74240C83CAFF833EFF7506F7DA8B742410833E00741A52B90A00000083EC2889E7ADF3A5FFD089FC8946D8588366D4005F5EC390909090909090909090'.decode('hex')
assert not len(_compar_code) & 15  # Good for alignment.


def get_mmap_constants(_cache=[]):
  if _cache:
    return _cache[-1]
  try:
    mmap = __import__('mmap')
  except ImportError:
    mmap = type(sys)('fake-mmap')
    pla = sys.platform
    if pla.startswith('linux'):
      mmap.PROT_READ, mmap.PROT_WRITE, mmap.PROT_EXEC = 1, 2, 4
      mmap.MAP_PRIVATE, mmap.MAP_ANON = 2, 0x20
    elif pla.startswith('darwin') or 'bsd' in pla:  # darwin is macOS.
      mmap.PROT_READ, mmap.PROT_WRITE, mmap.PROT_EXEC = 1, 2, 4
      mmap.MAP_PRIVATE, mmap.MAP_ANON = 2, 0x1000
  missing_names = [name for name in ('PROT_READ', 'PROT_WRITE', 'PROT_EXEC', 'MAP_PRIVATE', 'MAP_ANON')
                   if name not in mmap.__dict__]
  if missing_names:
    raise ImportError('Missing names in mmap module: %r' % missing_names)
  _cache.append(mmap)
  return mmap


class CallerDl(object):
  """Uses `import dl'. Works in Python 2 on i386 Unix (not Windows) only."""

  __slots__ = ('vp', 'd_call', 'size', 'vp_compar', 'vp_addr_map')

  def __init__(self, native_code, addr_map):
    self.vp = 0
    if not isinstance(native_code, str):
      raise TypeError
    if not isinstance(addr_map, dict):
      raise TypeError
    dl = __import__('dl') # 32-bit, Unix, Python 2 only.  !! Verify.
    mmap = get_mmap_constants()
    d = dl.open('')
    missing_names = []
    try:
      # Regular `import dl' doesn't support int as the 1st argument of
      # d.call, but the one in StaticPython does support it, and we can use it
      # for speedup.
      d.call(d.sym('memcpy'))  # 0 is the default for the remaining args.
      compar_ofs = -1
    except TypeError:
      if not d.sym('qsort'):
        missing_names.append('qsort')
      compar_ofs = (len(native_code) + 15) & ~15
      native_code += '\x90' * (compar_ofs - len(native_code)) + _compar_code
    missing_names.extend(name for name in ('mmap', 'mprotect', 'munmap', 'memcpy') if not d.sym(name))
    if missing_names:
      raise RuntimeError('CallerDl unusable, names %r missing.' % missing_names)
    self.d_call, self.size = d.call, len(native_code)
    self.vp = vp = d.call(
        'mmap', -1, len(native_code), mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
    if vp in (0, -1):
      raise RuntimeError('mmap failed.')
    d.call('memcpy', vp, native_code, len(native_code))
    if d.call('mprotect', vp, len(native_code), mmap.PROT_READ | mmap.PROT_EXEC):
      raise RuntimeError('mprotect failed.')
    if compar_ofs >= 0:
      self.vp_compar = vp + compar_ofs
    else:
      self.vp_compar = 0
    self.vp_addr_map = dict((k, vp + v) for k, v in addr_map.iteritems())

  def __del__(self):
    if self.vp not in (0, -1):
      self.d_call('munmap', self.vp, self.size)
      self.vp = 0
    # We can't call dlclose(3) directly, `import dl' doesn't have that.

  def callc(self, func_name, *args):
    """Args are int, str (bytes) or None."""
    # !! Populate methods directly instead.
    if self.vp_compar:  # Slow but compatible version with qsort.
      if len(args) > 10:  # d_call has a limit of 10 anyway.
        raise ValueError('At most 9 arguments accepted.')
      d_call = self.d_call
      a = [0] * 13
      for i, arg in enumerate(args):
        if isinstance(arg, str):
          arg = d_call('memcpy', arg)  # Convert data pointer to integer.
        a[i + 2] = arg
      a[0], a[1], a[12] = '=12l40x', self.vp_addr_map[func_name], -1
      qsort_data = struct.pack(*a)
      # It's not possible to pass a function pointer to d_call directly, so
      # qsort will call _compar_code, which will call func_name.
      d_call('qsort', qsort_data, 2, 44, self.vp_compar)
      return struct.unpack('=l', qsort_data[4 : 8])[0]
    else:  # Fast version with callr9, StaticPython-only.
      return self.d_call(self.vp_addr_map[func_name], *args)


class CallerCtypes(object):
  """Uses `import ctypes'. Works in Python >=2.5."""

  __slots__ = ('vp', 'size', 'munmap', 'vp_addr_map', 'vp_func_map', 'c_char_p')

  def __init__(self, native_code, addr_map):
    self.vp = 0
    if not isinstance(native_code, str):
      raise TypeError
    if not isinstance(addr_map, dict):
      raise TypeError
    ctypes = __import__('ctypes')
    # !! Add win32 support for ctypes, no mmap and especially 64-bit (different ABI).
    mmap = get_mmap_constants()
    self.munmap, self.size = ctypes.pythonapi['munmap'], len(native_code)
    self.munmap.argtypes = (ctypes.c_size_t, ctypes.c_size_t)
    mmap_func = ctypes.pythonapi['mmap']
    mmap_func.restype = ctypes.c_size_t
    if ctypes.pythonapi['mmap'].argtypes is not None:
      # Each time we use ctypes.pythonapi[...], we want to have a fresh
      # ctypes._FuncPtr object, to avoid making global changes.
      raise RuntimeError('Unusual global argtypes behavior detected.')
      # Doesn't change the original.
    self.vp = vp = mmap_func(
        -1, len(native_code), mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
    if self.vp == -1:
      raise RuntimeError('mmap failed.')
    ctypes.memmove(self.vp, native_code, len(native_code))
    mprotect = ctypes.pythonapi['mprotect']
    # Here it doesn't accept ctypes.c_char_p, but ctypes.c_char_p(42) is OK.
    mprotect.argtypes = (ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int)
    if mprotect(self.vp, len(native_code), mmap.PROT_READ | mmap.PROT_EXEC) == -1:  # !! Still passes self.vp as 32 bits.
      raise RuntimeError('mprotect failed.')
    self.vp_addr_map = dict((k, vp + v) for k, v in addr_map.iteritems())
    self.c_char_p = ctypes.c_char_p
    func_ret_int = ctypes.CFUNCTYPE(ctypes.c_size_t)  # 32 or 64 bits.
    self.vp_func_map = dict((k, func_ret_int(vp + v)) for k, v in addr_map.iteritems())

  def __del__(self):
    if self.vp:
      self.munmap(self.vp, self.size)
      self.vp = 0

  def callc(self, func_name, *args):
    return self.vp_func_map[func_name](*itertools.imap(self.c_char_p, args))


if __name__ == '__main__':
  # int addmul(int a, int b, int c, int d, int e, int f, int g, int h, int i) {
  #   return a * b + c * d + e * f + g * h + i;
  # }
  # TODO(pts): Check for i686.
  addmul_code = (
      # addmul:
      '8b542408'   # mov    0x8(%esp),%edx
      '8b442410'   # mov    0x10(%esp),%eax
      '0faf542404' # imul   0x4(%esp),%edx
      '0faf44240c' # imul   0xc(%esp),%eax
      '01d0'       # add    %edx,%eax
      '8b542418'   # mov    0x18(%esp),%edx
      '0faf542414' # imul   0x14(%esp),%edx
      '01d0'       # add    %edx,%eax
      '8b542420'   # mov    0x20(%esp),%edx
      '0faf54241c' # imul   0x1c(%esp),%edx
      '01d0'       # add    %edx,%eax
      '03442424'   # add    0x24(%esp),%eax
      'c3'         # ret
  ).decode('hex')

  addmul_amd64_code = (
      '0fafd1'      # imul   %ecx,%edx
      '8b4c2410'    # mov    0x10(%rsp),%ecx
      '0faf4c2408'  # imul   0x8(%rsp),%ecx
      '0faffe'      # imul   %esi,%edi
      '450fafc1'    # imul   %r9d,%r8d
      '01d7'        # add    %edx,%edi
      '4401c7'      # add    %r8d,%edi
      '8d040f'      # lea    (%rdi,%rcx,1),%eax
      '03442418'    # add    0x18(%rsp),%eax
      'c3'          # retq
  ).decode('hex')

  xorp32_code = (
      # xorp32:
      '8b442404'   # mov    0x4(%esp),%eax
      '8b542408'   # mov    0x8(%esp),%edx
      '8b12'       # mov    (%edx),%edx
      '3110'       # xor    %edx,(%eax)
      'c3'         # ret
  ).decode('hex')

  xorp32_amd64_code = (
      # xorp32_amd64:
      '8b06'       # mov    (%rsi),%eax
      '3107'       # xor    %eax,(%rdi)
      'c3'         # retq
  ).decode('hex')

  print addmul(13, 12, 11, 10, 9, 8, 7, 6, 5)  #: 385
  print addmul(5, 6, 7, 8, 9, 10, 11, 12, 13)  #: 321

  native_code = addmul_code + xorp32_code + xorp32_amd64_code + addmul_amd64_code
  addr_map = {'addmul': 0, 'xorp32': len(addmul_code), 'xorp32_amd64': len(addmul_code) + len(xorp32_code), 'addmul_amd64': len(addmul_code) + len(xorp32_code) + len(xorp32_amd64_code)}

  if 1:
    caller = CallerDl(native_code, addr_map)
    print caller.callc('addmul', 5, 6, 7, 8, 9, 10, 11, 12, 13)
    sa = 'ABCD' + chr(0)  # !! Create unique string object faster: str(buffer(...))?
    sb = 'dcba'
    caller.callc('xorp32', sa, sb)
    print [sa, sb]  #: ['%!!%\x00', 'dcba'].

  if 0:
    caller = CallerCtypes(native_code, addr_map)
    print caller.callc('addmul_amd64', 5, 6, 7, 8, 9, 10, 11, 12, 13)
    sa = 'ABCD' + chr(0)  # !! Create unique string object faster: str(buffer(...))?
    sb = 'dcba'
    caller.callc('xorp32_amd64', sa, sb)
    print [sa, sb]  #: ['%!!%\x00', 'dcba'].
