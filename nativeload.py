#! /usr/bin/python
# by pts@fazekas.hu at Sat Dec 14 14:07:10 CET 2019
# !! Make this 

import dl # 32-bit, Unix, Python 2 only.  !! Verify.
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


class CallerDl(object):
  """Uses `import dl'. Works in Python 2 on i386 Unix (not Windows) only."""

  __slots__ = ('vp', 'd_call', 'size', 'vp_compar', 'vp_addr_map')

  def __init__(self, native_code, addr_map):
    self.vp = 0
    if not isinstance(native_code, str):
      raise TypeError
    if not isinstance(addr_map, dict):
      raise TypeError
    compar_ofs = (len(native_code) + 15) & ~15
    native_code += '\x90' * (compar_ofs - len(native_code)) + _compar_code  # !! Omit _compar_code if not needed.
    # !! Linux. Is macOS different?
    import mmap  # For constants only.
    d = dl.open('')
    assert d.sym('mmap')
    assert d.sym('mprotect')
    assert d.sym('munmap')
    assert d.sym('memcpy')
    assert d.sym('qsort')
    vp = d.call('mmap', 0, len(native_code),
                 mmap.PROT_READ | mmap.PROT_WRITE,
                 mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
    assert vp != 0
    assert vp != -1
    self.vp, self.d_call, self.size = vp, d.call, len(native_code)
    d.call('memcpy', vp, native_code, len(native_code))
    d.call('mprotect', vp, len(native_code), mmap.PROT_READ | mmap.PROT_EXEC)
    self.vp_compar = vp + compar_ofs
    self.vp_addr_map = dict((k, vp + v) for k, v in addr_map.iteritems())

  def __del__(self):
    if self.vp:
      self.d_call('munmap', self.vp, self.size)
      self.vp = 0
    # We can't call dlclose(3) directly, `import dl' doesn't have that.

  def callc1(self, func_name, *args):  # Uses vp, d_call, vp_addr_map.
    # !! Populate methods directly instead.
    a = ['callr9']
    a.extend(args)
    padc = 10 - len(a)
    if padc:
      if padc < 0:
        raise ValueError('At most 9 arguments accepted.')
      a.extend((0, 0, 0, 0, 0, 0, 0, 0, 0, 0)[:padc])
    a.append(self.vp_addr_map[func_name])
    return self.d_call(*a)

  def callc2(self, func_name, *args):  # Uses vp, d_call, vp_compar, vp_addr_map.
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

  print addmul(13, 12, 11, 10, 9, 8, 7, 6, 5)  #: 385
  print addmul(5, 6, 7, 8, 9, 10, 11, 12, 13)  #: 321
  caller = CallerDl(addmul_code + xorp32_code, {'addmul': 0, 'xorp32': len(addmul_code)})

  print caller.callc1('addmul', 5, 6, 7, 8, 9, 10, 11, 12, 13)
  print caller.callc2('addmul', 5, 6, 7, 8, 9, 10, 11, 12, 13)

  sa = 'ABCD' + chr(0)  # !! Create unique string object faster: str(buffer(...))?
  sb = 'dcba'
  caller.callc1('xorp32', sa, sb)
  print [sa, sb]  #: ['%!!%\x00', 'dcba'].

  sa = 'ABCD' + chr(0)  # !! Create unique string object faster: str(buffer(...))?
  sb = 'dcba'
  caller.callc2('xorp32', sa, sb)
  print [sa, sb]  #: ['%!!%\x00', 'dcba'].