#! /usr/bin/python
# by pts@fazekas.hu at Sat Dec 14 14:07:10 CET 2019
# !! Make this 

import dl # 32-bit, Unix, Python 2 only.  !! Verify.
import struct

def addmul(a, b, c, d, e, f, g, h, i):
  r = a * b + c * d + e * f + g * h + i
  return (r & 0x7fffffff) - (r & 0x80000000)  # Sign-extend.

# int addmul(int a, int b, int c, int d, int e, int f, int g, int h, int i) {
#   return a * b + c * d + e * f + g * h + i;
# }
# TODO(pts): Check for i686.
addmul_code = (
    # compar:  # TODO(pts): Make it smaller.
    # int compar(struct args *a, struct args *b) {
    #   if (b->v & 1) a = b;
    #   if (a->v & 1) {
    #     a->v &= 6;  /* Don't trigger again. */
    #     a->a = a->p(a->a, a->b, a->c, a->d, a->e, a->f, a->g, a->h, a->i);
    #   }
    #   return 0;
    # }
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
    'c3'         # ret, will be skipped
    'c3'         # ret, will be skipped
    'c3'         # ret, will be skipped
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
    # xorp32:
    '8b442404'   # mov    0x4(%esp),%eax
    '8b542408'   # mov    0x8(%esp),%edx
    '8b12'       # mov    (%edx),%edx
    '3110'       # xor    %edx,(%eax)
    'c3'         # ret    
).decode('hex')

print addmul(13, 12, 11, 10, 9, 8, 7, 6, 5)  #: 385
print addmul(5, 6, 7, 8, 9, 10, 11, 12, 13)  #: 321

def test_native_dl():
  # !! Linux. Is macOS different?
  import mmap  # For constants only.
  d = dl.open('')  # !! StaticPython-only.
  assert d.sym('mmap')
  assert d.sym('mprotect')
  assert d.sym('munmap')
  assert d.sym('memcpy')
  assert d.sym('qsort')
  # TODO(pts): Call munmap later.
  class MmapReleaser(object):
    __slots__ = ('p', 'd_call', 'size')
    def __init__(self, p, d_call, size):
      self.p, self.d_call, self.size = int(p), d_call, int(size)
    def __del__(self):
      self.d_call('munmap', self.p, self.size)
  vp = d.call('mmap', 0, len(addmul_code),
               mmap.PROT_READ | mmap.PROT_WRITE,
               mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
  assert vp != 0
  assert vp != -1
  m = MmapReleaser(vp, d.call, len(addmul_code))
  d.call('memcpy', vp, addmul_code, len(addmul_code))
  d.call('mprotect', vp, len(addmul_code), mmap.PROT_READ | mmap.PROT_EXEC)
  vp_compar = vp
  vp_addmul = vp + addmul_code.find('\xc3\xc3\xc3\x8b\x54') + 3
  vp_xord32 = vp + addmul_code.find('\xc3\xc3\xc3\x8b\x44') + 3
  d_call = d.call


  def callc1(vp_func, *args):  # Uses d_call.
    a = ['callr9']
    a.extend(args)
    padc = 10 - len(a)
    if padc:
      if padc < 0:
        raise ValueError('At most 9 arguments accepted.')
      a.extend((0, 0, 0, 0, 0, 0, 0, 0, 0, 0)[:padc])
    a.append(vp_func)
    return d_call(*a)

  def callc2(vp_func, *args):  # Uses vp_compar. # !! Align it to 16.
    if len(args) > 9:
      raise ValueError('At most 9 arguments accepted.')
    a = [0] * 22
    for i, arg in enumerate(args):
      if isinstance(arg, str):
        arg = d.call('memcpy', arg, 0, 0)  # Convert data pointer to integer.
      a[i + 1] = arg
    a[0], a[10], a[11] = 3, vp_func, 4
    qsort_data = struct.pack('=22l', *a)
    d_call('qsort', qsort_data, 2, 44, vp_compar)
    return struct.unpack('=l', qsort_data[4 : 8])[0]

  args = (5, 6, 7, 8, 9, 10, 11, 12, 13, vp_addmul)
  print d.call('callr9', *args)  # :321
  print callc1(vp_addmul, 5, 6, 7, 8, 9, 10, 11, 12, 13)
  print callc2(vp_addmul, 5, 6, 7, 8, 9, 10, 11, 12, 13)

  sa = 'ABCD' + chr(0)  # !! Create unique string object faster: str(buffer(...))?
  sb = 'dcba'
  callc1(vp_xord32, sa, sb)
  print [sa, sb]  #: ['%!!%\x00', 'dcba'].

  sa = 'ABCD' + chr(0)  # !! Create unique string object faster: str(buffer(...))?
  sb = 'dcba'
  callc2(vp_xord32, sa, sb)
  print [sa, sb]  #: ['%!!%\x00', 'dcba'].


test_native_dl()
