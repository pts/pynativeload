#! /usr/bin/python
# by pts@fazekas.hu at Sat Dec 14 14:07:10 CET 2019
#
# !! Make this work in Python 3 with ctypes.
# !! Add helper for returning a new byte string.
#

import itertools
import struct
import sys


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
  """Uses `import dl'. Works in Python 2 on i386 Unix (not Windows) only.

  See more docstrings of NativeExtCtypes.
  """

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
  _compar_code = '56578b74240c83caff833eff7506f7da8b742410833e00741a52b90a00000083ec2889e7adf3a5ffd089fc8946d8588366d4005f5ec3'.decode('hex')
  # See source in gdolow.c.
  _gdolow_code = '5589e55653538b5d088b43048b5004395204740b8b430c83c3088b7058eb038b705085f6750431c0eb2b837e0c0074f68b460885c074ef6a0053ffd05a594875e58d45f4506a0053ff560c83c40c85c078d48b45f48d65f85b5e5dc3'.decode('hex')

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
    d_call, missing_names, alloc_size, trampoline_ofs, gdolow_ofs = d.call, [], len(native_code), -1, -1
    if d.sym('memmove'):
      try:
        # Regular `import dl' doesn't support int as the 1st argument of
        # d_call, but the one in StaticPython does support it, and we can use it
        # for speedup.
        d_call(d.sym('memmove'))  # 0 is the default for the remaining args.
        d_call('memmove', buffer(''))  # If this raises a TypeError, then _gdolow_code is needed.
        d_call('memmove', 0L)  # TypeError in original dl.
      except TypeError:
        if not d.sym('qsort'):
          missing_names.append('qsort')
        trampoline_ofs, trampoline = alloc_size, self._compar_code
        gdolow_ofs, gdolow = trampoline_ofs + len(trampoline), self._gdolow_code
        alloc_size = trampoline_ofs + gdolow_ofs + len(gdolow)
    else:
      missing_names.append('memmove')
    missing_names.extend(name for name in ('mmap', 'mprotect', 'munmap') if not d.sym(name))
    if missing_names:
      raise RuntimeError('NativeExtDl unusable, names %r missing.' % missing_names)
    vp = d_call(
        'mmap', -1, alloc_size, mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
    if vp in (0, -1):
      raise RuntimeError('mmap failed.')
    self._del_func, self._del_args = d_call, ('munmap', vp, alloc_size)
    d_call('memmove', vp, native_code, len(native_code))
    if trampoline_ofs >= 0:
      d_call('memmove', vp + trampoline_ofs, trampoline, len(trampoline))
    if gdolow_ofs >= 0:
      d_call('memmove', vp + gdolow_ofs, gdolow, len(gdolow))
    if d_call('mprotect', vp, alloc_size, mmap.PROT_READ | mmap.PROT_EXEC):
      raise RuntimeError('mprotect failed.')
    self.dc = dc = {}

    def _build_call(func_name, func_ptr, d_call):
      def dl_call(*args):
        return d_call(func_ptr, *args)

      dl_call.__name__ = func_name
      return dl_call

    def _build_call_qsort(func_name, func_ptr, d_call, vp_compar, pack=struct.pack, unpack=struct.unpack):
      def dl_call(*args):
        if len(args) > 10:  # d_call has a limit of 10 anyway.
          raise ValueError('At most 10 arguments accepted.')
        a = [0] * 13
        for i, arg in enumerate(args):
          if isinstance(arg, str):
            arg = d_call('memmove', arg)  # Convert data pointer to integer.
          elif isinstance(arg, long):
            arg = int(arg)
          a[i + 2] = arg
        a[0], a[1], a[12] = '=12l40x', func_ptr, -1
        qsort_data = pack(*a)
        d_call('qsort', qsort_data, 2, 44, vp_compar)
        return unpack('=l', qsort_data[4 : 8])[0]

      dl_call.__name__ = func_name
      return dl_call

    def _build_memmove_with_trampoline(gdolow_func, d_call, memmove_doc, normal_types=(int, long, str, type(None))):
      def memmove(dst, src=0, size=0):
        if not isinstance(dst, normal_types):
          #buffer(dst)  # May raise TypeError. Good.
          dst = id(dst)
          dst = gdolow_func((dst & 0x7fffffff) - (dst & 0x80000000))
          if not dst:
            raise TypeError('Byte string or buffer expected.')
        if not isinstance(src, normal_types):
          #buffer(dst)  # May raise TypeError. Good.
          src = id(src)
          src = gdolow_func((src & 0x7fffffff) - (src & 0x80000000))
          if not src:
            raise TypeError('Byte string or buffer expected.')
        return d_call('memmove', dst, src, size)

      memmove.__doc__ = memmove_doc
      return memmove

    memmove_doc = self.memmove.__doc__
    if trampoline_ofs >= 0:
      # It's not possible to pass a function pointer to d_call directly, so
      # qsort will call self._compar_code, which will call func_name.
      vp_trampoline = vp + trampoline_ofs
      for func_name, v in addr_map.iteritems():
        dc[func_name] = _build_call_qsort(func_name, vp + v, d_call, vp_trampoline)
      gdolow_func = _build_call_qsort('__godlow__', vp + gdolow_ofs, d_call, vp_trampoline)
      self.memmove = _build_memmove_with_trampoline(gdolow_func, d_call, memmove_doc)
    else:
      for func_name, v in addr_map.iteritems():
        dc[func_name] = _build_call(func_name, vp + v, d_call)
      self.memmove = _build_call('memmove', d.sym('memmove'), d_call)
      self.memmove.__doc__ = memmove_doc
    d = self.__dict__
    for k, v in dc.iteritems():
      if not (k.startswith('__') and k.endswith('__')) and getattr(self, k, None) is None:
        d[k] = v
    #self.__getitem__ = str  # This makes no difference, the class needs to have it.

  def __del__(self):
    self._del_func(*self._del_args)
    # We can't call dlclose(3) directly, `import dl' doesn't have that.

  def __getitem__(self, key):
    return self.dc[key]

  def memmove(self, dst, src=0, size=0):
    """Copies bytes, also accepts buffer, returns address of dst as int.

    Can be used to pass the data pointer of a buffer:

      self.native_func(self.memmove(bytes_or_buffer_obj))
    """
    raise RuntimeError('Should be overridden in __init__.')

  @staticmethod
  def id(buf):
    """Returns the integer PyObject* value, signed or unsigned."""
    r = id(buf)
    return (r & 0x7fffffff) - (r & 0x80000000)


class NativeExtCtypes(object):
  """Uses `import ctypes'. Works in Python >=2.5."""

  # Trampoline to call System V amd64 ABI functions from ctypes calling as Windows amd64.
  #  gcc -m64 -Os -W -Wall -Werror -fomit-frame-pointer -mno-sse -c t.c && objdump -d t.o */
  # __attribute__((ms_abi)) long passms10(long a, long b, long c, long d, long e, long f, long g, long h, long i, long j,
  #                                       long (*fs)(long a, long b, long c, long d, long e, long f, long g, long h, long i, long j)) {
  # return fs(a, b, c, d, e, f, g, h, i, j);
  # }
  _win64_trampoline_code = '574889cf4c89c9564889d64c89c24883ec28488b8424880000004c8b4c24684c8b4424604889442418488b8424800000004889442410488b4424784889442408488b44247048890424ff9424900000004883c4285e5fc3'.decode('hex')

  def __init__(self, native_code, addr_map):
    # This code works for both 32-bit (x86) and 64-bit (amd64).
    # TODO(pts): arm has relative jumps and calls, mips has absolute jumps and
    #    calls (but relative conditional branches); how does -fpic work?
    #    relative jumps to avoid relocations usses. Relocate manually in Python?
    # TODO(pts): Add at least newlib for memmove.
    # TODO(pts): !! Check it for arm (e.g. Raspberry Pi) Linux, it should also work.
    # TODO(pts): Check it for arm (e.g. Raspberry Pi) Windows, it should also work.
    self._del_func, self._del_args = lambda: 0, ()  # Everything else is from addr_map.
    if not isinstance(native_code, str):
      raise TypeError
    if not isinstance(addr_map, dict):
      raise TypeError
    ctypes = __import__('ctypes')
    if ctypes.sizeof(ctypes.c_voidp) != struct.calcsize('P'):
      raise ValueError('Pointer size mismatch.')

    def with_res_size_t(api_func):
      api_func.restype = cst  # Without this return values in 64-bit mode would be truncated to 32 bits (both Linux and Windows).
      return api_func

    def _build_call(func_name, vp_func, imap, c_char_p, fri):
      def ctypes_call(*args):
        # c_char_p can take int or str, good.
        return func_obj(*imap(c_char_p, args))

      func_obj = fri(vp_func)
      ctypes_call.__name__ = func_name
      return ctypes_call

    def _build_call_win64(func_name, vp_func, imap, c_char_p, fri):
      def ctypes_call(*args):
        la = len(args)
        if la > 10:
          raise ValueError('At most 10 arguments accepted.')
        a = targs[:]
        a[:la] = imap(c_char_p, args)
        return fri(*a)  # Call _win64_trampoline_code on a.

      targs = [0] * 11
      targs[10] = vp_func
      ctypes_call.__name__ = func_name
      return ctypes_call

    def _build_memmove(memmove_doc, ctypes=ctypes, normal_types=(int, long, str, type(None))):
      def memmove(dst, src=0, count=0):
        if not isinstance(dst, normal_types):
          data = ctypes.c_void_p()
          #assert ctypes.pythonapi.PyObject_CheckReadBuffer(ctypes.c_size_t(id(dst))), [dst]
          #assert ctypes.pythonapi.PyObject_CheckReadBuffer(ctypes.py_object(dst)), [dst]
          ctypes.pythonapi.PyObject_AsCharBuffer(  # Raises TypeError if needed.
              ctypes.py_object(dst), ctypes.pointer(data),
              ctypes.pointer(ctypes.c_size_t()))
          dst = data.value
        if not isinstance(src, normal_types):
          data = ctypes.c_void_p()
          ctypes.pythonapi.PyObject_AsCharBuffer(  # Raises TypeError if needed.
              ctypes.py_object(src), ctypes.pointer(data),
              ctypes.pointer(ctypes.c_size_t()))
          src = data.value
        return ctypes.memmove(dst, src, count)

      memmove.__doc__ = memmove_doc
      return memmove

    imap = __import__('itertools').imap
    build_call, vp_trampoline, cst = _build_call, None, ctypes.c_size_t
    if sys.platform.startswith('win'):
      arch = get_arch()
      if arch not in ('x86', 'amd64'):
        # Python can be built on arm64 as well, but there are no official
        # release (https://bugs.python.org/issue33125), so it would be hard
        # to test ABI etc. with nativeload.
        raise RuntimeError('On Windows only x86 is supported.')
      MEM_COMMIT, MEM_RESERVE, MEM_RELEASE = 0x1000, 0x2000, 0x8000
      PAGE_READWRITE, PAGE_EXECUTE_READ = 4, 0x20
      alloc_size = len(native_code)
      if arch == 'amd64':
        assert struct.calcsize('P') == 8
        trampoline_ofs, trampoline = (alloc_size + 15) & ~15, self._win64_trampoline_code
        alloc_size = trampoline_ofs + len(trampoline)
      vp = with_res_size_t(ctypes.windll.kernel32['VirtualAlloc'])(0, cst(alloc_size), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
      if not vp:
        raise RuntimeError('VirtualAlloc failed: %d' % ctypes.windll.kernel32.GetLastError())
      self._del_func, self._del_args = ctypes.windll.kernel32['VirtualFree'], (cst(vp), 0, MEM_RELEASE)
      ctypes.memmove(vp, native_code, len(native_code))
      if arch == 'amd64':
        build_call, vp_trampoline = _build_call_win64, vp + trampoline_ofs
        ctypes.memmove(vp_trampoline, trampoline, len(trampoline))
      if not ctypes.windll.kernel32['VirtualProtect'](cst(vp), cst(alloc_size), PAGE_EXECUTE_READ, ctypes.addressof(cst(0))):
        raise RuntimeError('VirtualProtect failed: %d' % ctypes.windll.kernel32.GetLastError())
    else:
      mmap = get_mmap_constants()
      vp = with_res_size_t(ctypes.pythonapi['mmap'])(
          -1, len(native_code), mmap.PROT_READ | mmap.PROT_WRITE,
          mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
      if vp in (0, -1):
        raise RuntimeError('mmap failed.')
      self._del_func, self._del_args = with_res_size_t(ctypes.pythonapi['munmap']), (cst(vp), cst(len(native_code)))
      ctypes.memmove(vp, native_code, len(native_code))
      # Here it doesn't accept ctypes.c_char_p, but ctypes.c_char_p(42) is OK.
      if with_res_size_t(ctypes.pythonapi['mprotect'])(cst(vp), cst(len(native_code)), mmap.PROT_READ | mmap.PROT_EXEC) == -1:
        raise RuntimeError('mprotect failed.')
    c_char_p = ctypes.c_char_p
    # !! Add per function option to release the GIL.
    # Use PYFUNCTYPE instead of CFUNCTYPE so that the GIL won't be released.
    # dl doesn't release the GIL either.
    # TODO(pts): Does it affect Windows?
    # TODO(pts): Does it affect exceptions being raised (incompatible to dl).
    self.dc = dc = {}
    c_char_p, fri = ctypes.c_char_p, ctypes.PYFUNCTYPE(cst)
    if vp_trampoline:
      fri = fri(vp_trampoline)
    for func_name, v in addr_map.iteritems():
      dc[func_name] = build_call(func_name, vp + v, imap, c_char_p, fri)
    self.id = id  # Set it early so it doesn't get overridden.
    self.memmove = _build_memmove(self.memmove.__doc__)
    d = self.__dict__
    for k, v in dc.iteritems():
      if not (k.startswith('__') and k.endswith('__')) and getattr(self, k, None) is None:
        d[k] = v

  def __del__(self):
    self._del_func(*self._del_args)

  def __getitem__(self, key):
    return self.dc[key]

  def memmove(self, dst, src=0, size=0):
    """Copies bytes, also accepts buffer, returns address of dst as int.

    Can be used to pass the data pointer of a buffer:

      self.native_func(self.memmove(bytes_or_buffer_obj))
    """
    raise RuntimeError('Should be overridden in __init__.')

  def id(self, obj):
    """Returns the integer PyObject* value, signed or unsigned."""
    raise RuntimeError('Should be overridden in __init__.')


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
      arch = os.getenv('PROCESSOR_IDENTIFIER', '').lower().split(None, 1)[0]
    if 'x86' in arch or '386' in arch or '486' in arch or '586' in arch or '686' in arch or 'ia32' in arch or 'em64t' in arch or 'amd64' in arch or 'x64' in arch:
      arch = 'x86'
    elif ('ia64' in arch or 'ia16' in arch or '286' in arch or '186' in arch or
          '086' in arch or 'arm' in arch or 'mips' in arch or 'risc' in arch or
          'x32' in arch or 'sparc' in arch or 's390' in arch or 'ppc' in arch or
          'powerpc' in arch or 'aarch' in arch):
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


def load_elf(filename, native_arch):
  import os
  import os.path
  if os.path.isfile(filename + '.objdump'):
    f = open(filename + '.objdump')
    try:
      data = f.read()
    finally:
      f.close()
  else:
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
  if native_arch and elf_arch != native_arch:
    raise ValueError('Architecture mismatch: elf=%s native=%s' % (elf_arch, get_arch()))
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
  import struct

  def addmul(a, b, c, d, e, f, g, h, i):
    r = a * b + c * d + e * f + g * h + i
    return (r & 0x7fffffff) - (r & 0x80000000)  # Sign-extend to 32 bits.

  assert addmul(13, 12, 11, 10, 9, 8, 7, 6, 5) == 385
  assert addmul(5, 6, 7, 8, 9, 10, 11, 12, -13) == 295

  arch = get_arch()
  if arch == 'x86':
    elf_arch, native_code, addr_map = load_elf('nexa32.elf', arch)
  elif arch == 'amd64':
    elf_arch, native_code, addr_map = load_elf('nexa64.elf', arch)
  else:
    raise ValueError('Native code missing for architecture: %s' % get_arch())
  #print elf_arch, sorted(addr_map.iteritems())

  native_ext = new_native_ext(native_code, addr_map)
  assert native_ext.addmul(0, 0, 0, 0, 0, 0, 0, 0, 0) == 0  # Works if no exception raised.
  assert native_ext.addmul(5, 6, 7, 8, 9, 10, 11, 12, -13L) == 295
  if struct.calcsize('P') > 4:
    assert native_ext.addmul(0, 0, 0, 0, 0, 0, 0, 0, 1 << 32 | 5) == (5 | 1 << 32)
  sa = 'ABCD' + chr(0)  # !! Create unique string object faster: str(buffer(...))?
  sb = 'dcba'
  native_ext['xorp32'](sa, sb)
  assert sa == '%!''!%\x00', [sa]
  assert sb == 'dcba', [sb]

  obj = object()
  assert (native_ext.id(obj) & ((1 << (struct.calcsize('P') * 8)) - 1)) == id(obj)

  assert native_ext.memmove('')  # Not 0.
  assert native_ext.memmove(sa) + 1 == native_ext.memmove(buffer(sa, 1))
  try:
    native_ext.memmove(())
    assert 0, 'TypeError not raised.'
  except TypeError:
    pass

  # TODO(pts): Debug and explain this.
  #import ctypes
  #ctypes.pythonapi.PyString_Repr(ctypes.py_object(42))
  #f = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.py_object)(ctypes.cast(ctypes.pythonapi.PyString_Size, ctypes.c_void_p).value)
  #print f('foo')  # Returns 3 both with PYFUNCTYPE and CFUNCTYPE.
  #print f('foo')  # Returns 3 both with PYFUNCTYPE and CFUNCTYPE.
  #print f('foo')  # Returns 3 both with PYFUNCTYPE and CFUNCTYPE.
  #print f(42)  # Raises with PYFUNCTYPE, segfault with CFUNCTYPE. Why?
