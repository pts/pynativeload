#! /usr/bin/python
# by pts@fazekas.hu at Sat Dec 14 14:07:10 CET 2019
# !! Make this 

import dl # 32-bit, Unix, Python 2 only.

def addmul(a, b, c, d, e, f, g, h, i):
  r = a * b + c * d + e * f + g * h + i
  return (r & 0x7fffffff) - (r & 0x80000000)  # Sign-extend.

# int addmul(int a, int b, int c, int d, int e, int f, int g, int h, int i) {
#   return a * b + c * d + e * f + g * h + i;
# }
# TODO(pts): Check for i686.
addmul_code = (
    # compar:  # TODO(pts): Make it smaller.
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
).decode('hex')

print addmul(13, 12, 11, 10, 9, 8, 7, 6, 5)  #: 385
print addmul(5, 6, 7, 8, 9, 10, 11, 12, 13)  #: 321

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
# Segmentation fault.
print d.call('callr9', 5, 6, 7, 8, 9, 10, 11, 12, 13, vp + addmul_code.find('\xc3\xc3\xc3\x8b') + 3)  # :321
