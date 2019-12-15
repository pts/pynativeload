#! /usr/bin/python
# by pts@fazekas.hu at Sat Dec 14 14:07:10 CET 2019
# !! Make this work in Python 3 with ctypes.

import itertools
import struct
import sys


def addmul(a, b, c, d, e, f, g, h, i):
  r = a * b + c * d + e * f + g * h + i
  return (r & 0x7fffffff) - (r & 0x80000000)  # Sign-extend.


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


class NativeExtDl(object):
  """Uses `import dl'. Works in Python 2 on i386 Unix (not Windows) only."""

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

  def __init__(self, native_code, addr_map):
    self._del_func, self._del_args = lambda: 0, ()  # Everything else is from addr_map.
    if not isinstance(native_code, str):
      raise TypeError
    if not isinstance(addr_map, dict):
      raise TypeError
    dl = __import__('dl') # 32-bit, Unix, Python 2 only.
    if 4 != struct.calcsize('P'):
      raise ValueError('Pointer size mismatch.')
    mmap = get_mmap_constants()
    d = dl.open('')
    d_call, missing_names = d.call, []
    try:
      # Regular `import dl' doesn't support int as the 1st argument of
      # d_call, but the one in StaticPython does support it, and we can use it
      # for speedup.
      d_call(d.sym('memcpy'))  # 0 is the default for the remaining args.
      compar_ofs = -1
    except TypeError:
      if not d.sym('qsort'):
        missing_names.append('qsort')
      compar_ofs = (len(native_code) + 15) & ~15
      native_code += '\x90' * (compar_ofs - len(native_code)) + self._compar_code
    missing_names.extend(name for name in ('mmap', 'mprotect', 'munmap', 'memcpy') if not d.sym(name))
    if missing_names:
      raise RuntimeError('NativeExtDl unusable, names %r missing.' % missing_names)
    vp = d_call(
        'mmap', -1, len(native_code), mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
    if vp in (0, -1):
      raise RuntimeError('mmap failed.')
    self._del_func, self._del_args = d_call, ('munmap', vp, len(native_code))
    d_call('memcpy', vp, native_code, len(native_code))
    if d_call('mprotect', vp, len(native_code), mmap.PROT_READ | mmap.PROT_EXEC):
      raise RuntimeError('mprotect failed.')
    if compar_ofs >= 0:
      # It's not possible to pass a function pointer to d_call directly, so
      # qsort will call self._compar_code, which will call func_name.
      _build_call_qsort, d, vp_compar = self._build_call_qsort, self.__dict__, vp + compar_ofs
      for func_name, v in addr_map.iteritems():
        d[func_name] = _build_call_qsort(func_name, vp + v, d_call, vp_compar)
    else:
      _build_call, d = self._build_call, self.__dict__
      for func_name, v in addr_map.iteritems():
        d[func_name] = _build_call(func_name, vp + v, d_call)

  def __del__(self):
    self._del_func(*self._del_args)
    # We can't call dlclose(3) directly, `import dl' doesn't have that.

  @staticmethod
  def _build_call(func_name, func_ptr, d_call):
    def dl_call(*args):
      return d_call(func_ptr, *args)

    dl_call.__name__ = func_name
    return dl_call

  @staticmethod
  def _build_call_qsort(func_name, func_ptr, d_call, vp_compar, pack=struct.pack, unpack=struct.unpack):
    def dl_call(*args):
      if len(args) > 10:  # d_call has a limit of 10 anyway.
        raise ValueError('At most 9 arguments accepted.')
      a = [0] * 13
      for i, arg in enumerate(args):
        if isinstance(arg, str):
          arg = d_call('memcpy', arg)  # Convert data pointer to integer.
        a[i + 2] = arg
      a[0], a[1], a[12] = '=12l40x', func_ptr, -1
      qsort_data = pack(*a)
      d_call('qsort', qsort_data, 2, 44, vp_compar)
      return unpack('=l', qsort_data[4 : 8])[0]

    dl_call.__name__ = func_name
    return dl_call


class NativeExtCtypes(object):
  """Uses `import ctypes'. Works in Python >=2.5."""

  def __init__(self, native_code, addr_map):
    # This code works on any architecture, both 32-bit and 64-bit (but
    # native_code must be valid for that architecture).
    self._del_func, self._del_args = lambda: 0, ()  # Everything else is from addr_map.
    if not isinstance(native_code, str):
      raise TypeError
    if not isinstance(addr_map, dict):
      raise TypeError
    ctypes = __import__('ctypes')
    if ctypes.sizeof(ctypes.c_voidp) != struct.calcsize('P'):
      raise ValueError('Pointer size mismatch.')
    imap = __import__('itertools').imap
    # !! Add win32 support for ctypes, no mmap and especially 64-bit (different ABI).
    mmap = get_mmap_constants()
    munmap = ctypes.pythonapi['munmap']
    # Without .argtypes and .restype in 64-bit mode, values would be
    # truncated to 32 bits.
    munmap.argtypes = (ctypes.c_size_t, ctypes.c_size_t)
    mmap_func = ctypes.pythonapi['mmap']
    mmap_func.restype = ctypes.c_size_t
    if ctypes.pythonapi['mmap'].argtypes is not None:
      # Each time we use ctypes.pythonapi[...], we want to have a fresh
      # ctypes._FuncPtr object, to avoid making global changes.
      raise RuntimeError('Unusual global argtypes behavior detected.')
      # Doesn't change the original.
    vp = mmap_func(
        -1, len(native_code), mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
    if vp in (0, -1):
      raise RuntimeError('mmap failed.')
    self._del_func, self._del_args = munmap, (vp, len(native_code))
    ctypes.memmove(vp, native_code, len(native_code))
    mprotect = ctypes.pythonapi['mprotect']
    # Here it doesn't accept ctypes.c_char_p, but ctypes.c_char_p(42) is OK.
    mprotect.argtypes = (ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int)
    if mprotect(vp, len(native_code), mmap.PROT_READ | mmap.PROT_EXEC) == -1:
      raise RuntimeError('mprotect failed.')
    c_char_p = ctypes.c_char_p
    _build_call, d, c_char_p, func_ret_int = self._build_call, self.__dict__, ctypes.c_char_p, ctypes.CFUNCTYPE(ctypes.c_size_t)
    for func_name, v in addr_map.iteritems():
      d[func_name] = _build_call(func_name, func_ret_int(vp + v), imap, c_char_p)

  def __del__(self):
    self._del_func(*self._del_args)

  @staticmethod
  def _build_call(func_name, func_obj, imap, c_char_p):
    def ctypes_call(*args):
      # c_char_p can take int or str, good.
      return func_obj(*imap(c_char_p, args))

    ctypes_call.__name__ = func_name
    return ctypes_call


def get_arch(_cache=[]):
  """For 64-bit systems running 32-bit Python, returns 32-bit arch."""
  if not _cache:
    os = __import__('os')
    platform = sys.platform
    try:
      arch = os.uname()[4].lower()
    except AttributeError:  # platform == 'win32' doesn't have it.
      arch = 'unknown'
    # There is also `import platform', but that's not smarter.
    if arch == 'unknown' and platform.startswith('win') and os.getenv('PROCESSOR_IDENTIFIER'):
      # This works for Windows XP and up. Also this returns 32 for 32-bit
      # Python on 64-bit system, good.
      arch = os.getenv('PROCESSOR_IDENTIFIER', '').lower()
    if 'x86' in arch or '386' in arch or '486' in arch or '586' in arch or '686' in arch or 'ia32' in arch or 'em64t' in arch:
      arch = 'x86'
    elif ('ia64' in arch or 'ia16' in arch or '286' in arch or '186' in arch or
          '086' in arch or 'arm' in arch or 'mips' in arch or 'risc' in arch or
          'x32' in arch or 'sparc' in arch or 's390' in arch or 'ppc' in arch or
          'powerpc' in arch):
      # ia64 is Itanium, not compatible with amd64.
      arch = 'other-' + arch
    else:
      arch = 'unknown-' + arch
    size = struct.calcsize('P') << 3
    #except struct.error:  # Python older than 2.4.
    #size = struct.calcsize('L')
    arch += '-%dbit' % size
    if arch == 'x86-64bit':
      arch = 'amd64'
    elif arch == 'x86-32bit':
      arch = 'x86'  # Can be i386, but that's more specific: i386 ... i686.
    _cache.append(arch)
  return _cache[-1]


def new_native_ext(native_code, addr_map, _cache=[]):
  arch = get_arch()
  if arch not in ('x86', 'amd64'):
    raise RuntimeError('Architecture not supported: %s' % arch)
  if not _cache:
    try:
      __import__('ctypes')
      _cache.append(NativeExtCtypes)
    except ImportError:
      if arch == 'amd64':
        raise ValueError('ctypes needed on architecture: ' % arch)
      try:
        __import__('dl')
        _cache.append(NativeExtDl)
      except ImportError:
        raise ImportError('Either ctypes or dl is needed.')
  # !! Check bounds of addr_map here.
  return _cache[-1](native_code, addr_map)


def load_elf(filename):
  subprocess = __import__('subprocess')
  objdump_cmd = ('objdump', '-x', '--', filename)
  p = subprocess.Popen(objdump_cmd, stdout=subprocess.PIPE)  # !! Do it in Python code.
  try:
    data = p.stdout.read()
  finally:
    exit_code = p.wait()
  if exit_code:
    raise RuntimeError('objdump_cmd %r failed with exit code %d.' % (objdump_cmd, exit_code))
  data = data.replace('\n      ', '      ').rstrip('\n').replace('\nSYMBOL TABLE:\n', '\n\nSYMBOL TABLE:\n').replace('\n\n\n', '\n\n').replace('\n\n', '\n\nBLOCK ')
  block = 'header'
  elf_arch = None
  text_addr = text_file_ofs = text_size = None
  addr_map = {}
  for line in data.split('\n'):
    if not line:
      pass
    elif line.startswith('architecture:') and block == 'header':
      elf_arch = line.split()[1].rstrip(',')
      if elf_arch == 'i386:x86-64':
        elf_arch = 'amd64'
      elif elf_arch == 'i386':
        elf_arch = 'x86'
    elif line.startswith('BLOCK ') and line.endswith(':'):
      block = line[6 : - 1]
    elif block == 'Sections':
      if not line.startswith('Idx'):
        items = line.split()
        i, name, size, vma, lma, file_ofs = int(items[0]), items[1], int(items[2], 16), int(items[3], 16), int(items[4], 16), int(items[5], 16)
        if name != '.text':
          raise ValueError('Only .text section expected, found %r; please get rid of global variables.' % name)
        text_addr, text_file_ofs, text_size = lma, file_ofs, size
    elif block == 'SYMBOL TABLE':
      items = line.split()
      if items[2][0] in '*.':
        items[2 : 2] = ('',)   # No flags.
      if len(items) >= 6:
        addr, stype, flags, section, size, name = int(items[0], 16), items[1], items[2], items[3], int(items[4], 16), items[5]
        if stype == 'g' and 'F' in flags and section == '.text':
          #print (addr, size, name)
          addr_map[name] = addr - text_addr  # !! Check bounds here.
    #elif line:
    #  print [block, line]
  f = open(filename, 'rb')
  try:
    f.seek(text_file_ofs)
    native_code = f.read(text_size)
  finally:
    f.close()
  if len(native_code) < text_size:
    raise ValueError('File too short for .text section.')
  return elf_arch, native_code, addr_map


if __name__ == '__main__':
  print addmul(13, 12, 11, 10, 9, 8, 7, 6, 5)  #: 385
  print addmul(5, 6, 7, 8, 9, 10, 11, 12, -13)  #: 295

  if get_arch() == 'x86':
    elf_arch, native_code, addr_map = load_elf('nexa32.elf')
  elif get_arch() == 'amd64':
    elf_arch, native_code, addr_map = load_elf('nexa64.elf')
  if elf_arch != get_arch():
    raise ValueError('Architecture mismatch: elf=%s native=%s' % (elf_arch, get_arch()))
  print elf_arch, sorted(addr_map.iteritems())

  native_ext = new_native_ext(native_code, addr_map)
  # !! SUXX: dl doesn't take long, fix it in StaticPython.
  print native_ext.addmul(5, 6, 7, 8, 9, 10, 11, 12, -13L)
  if get_arch() == 'amd64':
    print native_ext.addmul(0, 0, 0, 0, 0, 0, 0, 0, 1 << 32 | 5) ^ (1 << 32)  #: 5.
  sa = 'ABCD' + chr(0)  # !! Create unique string object faster: str(buffer(...))?
  sb = 'dcba'
  native_ext.xorp32(sa, sb)
  print [sa, sb]  #: ['%!!%\x00', 'dcba'].
