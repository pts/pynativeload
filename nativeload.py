#! /usr/bin/python
# by pts@fazekas.hu at Sat Dec 14 14:07:10 CET 2019
# !! Make this work in Python 3.

import struct


def addmul(a, b, c, d, e, f, g, h, i):
  r = a * b + c * d + e * f + g * h + i
  return (r & 0x7fffffff) - (r & 0x80000000)  # Sign-extend.

# Size divisible by 16, good for alignment.
_compar_code = (
    # compar:  # TODO(pts): Make it smaller.
    # int compar(struct args *a, struct args *b) {
    #   if (b->v & 1) a = b;
    #   if (a->v & 1) {
    #     a->v &= 6;  /* Don't trigger again. */
    #     a->a = a->p(a->a, a->b, a->c, a->d, a->e, a->f, a->g, a->h, a->i);
    #   }
    #   return 0;
    # }
    # !! Reuse a->p as null pointer, make it smaller.
    '53'         # push   %ebx
    '83ec38'     # sub    $0x38,%esp
    '8b5c2440'   # mov    0x40(%esp),%ebx
    '8b442444'   # mov    0x44(%esp),%eax
    'f60001'     # testb  $0x1,(%eax)
    '7402'       # je     d1 <compar+0x13>
    '89c3'       # mov    %eax,%ebx
    '8b03'       # mov    (%ebx),%eax
    'a801'       # test   $0x1,%al
    '7449'       # je     120 <compar+0x62>
    '83e006'     # and    $0x6,%eax
    '8903'       # mov    %eax,(%ebx)
    '8b4324'     # mov    0x24(%ebx),%eax
    '89442420'   # mov    %eax,0x20(%esp)
    '8b4320'     # mov    0x20(%ebx),%eax
    '8944241c'   # mov    %eax,0x1c(%esp)
    '8b431c'     # mov    0x1c(%ebx),%eax
    '89442418'   # mov    %eax,0x18(%esp)
    '8b4318'     # mov    0x18(%ebx),%eax
    '89442414'   # mov    %eax,0x14(%esp)
    '8b4314'     # mov    0x14(%ebx),%eax
    '89442410'   # mov    %eax,0x10(%esp)
    '8b4310'     # mov    0x10(%ebx),%eax
    '8944240c'   # mov    %eax,0xc(%esp)
    '8b430c'     # mov    0xc(%ebx),%eax
    '89442408'   # mov    %eax,0x8(%esp)
    '8b4308'     # mov    0x8(%ebx),%eax
    '89442404'   # mov    %eax,0x4(%esp)
    '8b4304'     # mov    0x4(%ebx),%eax
    '890424'     # mov    %eax,(%esp)
    'ff5328'     # call   *0x28(%ebx)
    '894304'     # mov    %eax,0x4(%ebx)
    '31c0'       # xor    %eax,%eax
    '83c438'     # add    $0x38,%esp
    '5b'         # pop    %ebx
    'c3'         # ret    
).decode('hex')
assert not len(_compar_code) % 15


# !! Add win32 support etc.


class CallerDl(object):
  """Uses `import dl'. Works in Python 2 on i386 Unix (not Windows) only."""

  __slots__ = ('vp', 'd_call', 'size', 'vp_compar', 'vp_addr_map')

  def __init__(self, native_code, addr_map):
    self.vp = 0
    if not isinstance(native_code, str):
      raise TypeError
    if not isinstance(addr_map, dict):
      raise TypeError
    import dl # 32-bit, Unix, Python 2 only.  !! Verify.
    # !! Linux. Is macOS different?
    import mmap  # For constants only.
    d = dl.open('')
    assert d.sym('mmap')  # !! No assert please.
    assert d.sym('mprotect')
    assert d.sym('munmap')
    assert d.sym('memcpy')
    assert d.sym('qsort')
    if d.sym('callr9'):
      compar_ofs = -1
    else:
      compar_ofs = (len(native_code) + 15) & ~15
      native_code += '\x90' * (compar_ofs - len(native_code)) + _compar_code  # !! Omit _compar_code if not needed.
    self.d_call, self.size = vp, d.call, len(native_code)
    self.vp = vp = d.call('mmap', 0, len(native_code),
                 mmap.PROT_READ | mmap.PROT_WRITE,
                 mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
    assert vp != 0
    assert vp != -1
    d.call('memcpy', vp, native_code, len(native_code))
    d.call('mprotect', vp, len(native_code), mmap.PROT_READ | mmap.PROT_EXEC)
    if compar_ofs >= 0:
      self.vp_compar = vp + compar_ofs
    else:
      self.vp_compar = 0
    self.vp_addr_map = dict((k, vp + v) for k, v in addr_map.iteritems())

  def __del__(self):
    if self.vp and self.vp != -1:
      self.d_call('munmap', self.vp, self.size)
      self.vp = 0
    # We can't call dlclose(3) directly, `import dl' doesn't have that.

  def callc(self, func_name, *args):
    """Args are int, str (bytes) or None."""
  
    # !! Populate methods directly instead.
    if self.vp_compar:  # Slow but compatible version with qsort.
      if len(args) > 9:
        raise ValueError('At most 9 arguments accepted.')
      d_call = self.d_call
      a = [0] * 22
      for i, arg in enumerate(args):
        if isinstance(arg, str):
          arg = d_call('memcpy', arg, 0, 0)  # Convert data pointer to integer.
        a[i + 1] = arg
      a[0], a[10], a[11] = 3, self.vp_addr_map[func_name], 4
      qsort_data = struct.pack('=22l', *a)
      d_call('qsort', qsort_data, 2, 44, self.vp_compar)
      return struct.unpack('=l', qsort_data[4 : 8])[0]
    else:  # Fast version with callr9, StaticPython-only.
      # !! Make it faster by using calll9, no need for a.extend.
      a = ['callr9']
      a.extend(args)
      padc = 10 - len(a)
      if padc:
        if padc < 0:
          raise ValueError('At most 9 arguments accepted.')
        a.extend((0, 0, 0, 0, 0, 0, 0, 0, 0, 0)[:padc])
      a.append(self.vp_addr_map[func_name])
      return self.d_call(*a)


class CallerCtypes(object):
  """Uses `import dl'. Works in Python 2 on i386 Unix (not Windows) only."""

  __slots__ = ('vp', 'size', 'munmap', 'vp_addr_map')

  def __init__(self, native_code, addr_map):
    self.vp = 0
    if not isinstance(native_code, str):
      raise TypeError
    if not isinstance(addr_map, dict):
      raise TypeError
    import ctypes
    #ctypes.pythonapi['mmap'].argtypes = ()
    #assert 0, ctypes.pythonapi['mmap'].argtypes
    #assert 0, dir(ctypes.pythonapi)
    # Method .from_buffer is missing in Python 2.5. Present in Python 2.6.
    import mmap  # !!
    self.munmap, self.size = ctypes.pythonapi.munmap, len(native_code)
    my_mmap = ctypes.pythonapi['mmap']
    my_mmap.restype = ctypes.c_long
    assert ctypes.pythonapi['mmap'].argtypes is None  # Doesn't change the original.
    #ctypes.pythonapi.mmap.restype = ctypes.c_long  # !! Pointer. Better get own function object.
    #ctypes.pythonapi.mprotect.argtypes = (ctypes.c_long, ctypes.c_long, ctypes.c_long)  # !!
    self.vp = vp = my_mmap(
        -1, len(native_code), mmap.PROT_READ | mmap.PROT_WRITE,
        mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)  # !! mprotect.
    if self.vp == -1:
      raise RuntimeError('mmap failed.')
    print ['A=0x%x\n' % self.vp]
    #ctypes.memmove(ctypes.c_char_p(self.vp), ctypes.addressof(ctypes.c_char_p.from_buffer(bytearray(native_code))), len(native_code))
    # !! Bad.
    #assert 0, (ctypes.c_char_p(self.vp), self.vp)
    #ctypes.memmove(self.vp, self.vp + 5, 5)  # !! What's wrong?
    #ctypes.pythonapi.malloc.restype = ctypes.c_long
    #self.vp = ctypes.pythonapi.malloc(42000000) # & 0xffffffffffffffff
    #print ['B=0x%x\n' % self.vp, self.vp, ctypes.c_char_p(self.vp)]
    #ctypes.pythonapi.memmove(ctypes.c_char_p(self.vp), ctypes.c_char_p(self.vp + 5), 5)  # !! What's wrong?
    #ctypes.memmove(ctypes.c_char_p(self.vp), ctypes.c_char_p(self.vp + 5), 5)  # !! What's wrong?
    ctypes.memmove(self.vp, native_code, len(native_code))
    #mprotect = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_long, ctypes.c_long)(ctypes.addressof(ctypes.pythonapi.mprotect))  # Doesn't work.
    #assert 0, ctypes.c_void_p(ctypes.pythonapi.mprotect)
    #assert 0, type(ctypes.pythonapi.mprotect); ctypes._FuncPtr
    #assert 0, (type(ctypes.pythonapi.mprotect), ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_long, ctypes.c_long, ctypes.c_long))
    #mprotect_int = ctypes.cast(ctypes.pythonapi.mprotect, ctypes.c_void_p).value  # Works.
    #mprotect_int = ctypes.pythonapi.mprotect  # Passes ptr as 32-bit. Doesn't work.
    # !! When to use WINFUNCTYPE?
    #mprotect = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_long, ctypes.c_long, ctypes.c_long)(mprotect_int)
    mprotect = ctypes.pythonapi['mprotect']
    mprotect.argtypes = (ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int)  # !! No more c_long.
    #assert 0, ctypes.WINFUNCTYPE
    #assert 0, type(mprotect)
    #assert 0, mprotect.argtypes
    #assert 0, ctypes.pythonapi.mprotect.argtypes
    #ctypes.pythonapi.mprotect(self.vp, len(native_code), mmap.PROT_READ | mmap.PROT_EXEC)
    if mprotect(self.vp, len(native_code), mmap.PROT_READ | mmap.PROT_EXEC) == -1:  # !! Still passes self.vp as 32 bits.
      raise RuntimeError('mprotect failed.')
    self.vp_addr_map = dict((k, vp + v) for k, v in addr_map.iteritems())
    #f = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_long, ctypes.c_long)(self.vp_addr_map['xorp32_amd64'])
    #assert 0, native_code[addr_map['xorp32_amd64']:].encode('hex')
    #f = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_char_p, ctypes.c_char_p)(self.vp_addr_map['xorp32_amd64'])  # Good.
    f = ctypes.CFUNCTYPE(ctypes.c_long)(self.vp_addr_map['xorp32_amd64'])
    #print f
    sa = 'ABCD' + chr(0)  # !! Create unique string object faster: str(buffer(...))?
    sb = 'dcba'
    #sa = bytearray(sa)
    #sb = bytearray(sb)
    #f(ctypes.addressof(ctypes.c_char_p(sa)), ctypes.addressof(ctypes.c_char_p(sb)))
    #f(ctypes.c_long(ctypes.c_char_p(sa)), ctypes.c_long(ctypes.c_char_p(sb)))
    #ctypes.memmove(ctypes.c_char_p(sa), ctypes.c_char_p(sb), 4)  # Works.
    #ctypes.pythonapi.memmove(ctypes.c_char_p(sa), ctypes.c_char_p(sb), 4)  # Works.
    #f(ctypes.c_char_p(sa), ctypes.c_char_p(sb))  # Good.
    #f(sa, sb)
    sai = ctypes.cast(ctypes.c_char_p(sa), ctypes.c_void_p).value
    sbi = ctypes.cast(ctypes.c_char_p(sb), ctypes.c_void_p).value
    #assert sai >> 32
    #print 'sbi=0x%x' % sbi
    f(sa, ctypes.c_char_p(sbi))
    #assert 0, ctypes.c_long(None)  # Error.    f(sa, sb)  # Good.
    print [sa, sb]  #: ['%!!%\x00', 'dcba'].

  def __del__(self):
    if self.vp:
      self.munmap(self.vp, self.size)
      self.vp = 0


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
      'c3'         # ret, will be skipped
      'c3'         # ret, will be skipped
      'c3'         # ret, will be skipped
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

  if 0:
    caller = CallerDl(addmul_code + xorp32_code + xorp32_amd64_code, {'addmul': 0, 'xorp32': len(addmul_code), 'xorp32_amd64': len(addmul_code) + len(xorp32_code)})
    print caller.callc('addmul', 5, 6, 7, 8, 9, 10, 11, 12, 13)
    sa = 'ABCD' + chr(0)  # !! Create unique string object faster: str(buffer(...))?
    sb = 'dcba'
    caller.callc('xorp32', sa, sb)
    print [sa, sb]  #: ['%!!%\x00', 'dcba'].

  caller = CallerCtypes(addmul_code + xorp32_code + xorp32_amd64_code, {'addmul': 0, 'xorp32': len(addmul_code), 'xorp32_amd64': len(addmul_code) + len(xorp32_code)})
