import sys
from subprocess import Popen, PIPE
from random import Random



key_lens = (128, 192, 256)
modes = ("ecb",)
cipher_format = "-aes-%d-%s"

test_cases = (
    "\x10",
    "\x10"*2,
    "\x10"*15,
    "\x10"*16,
    "\x10"*31,
    "\x10"*32,
    "\xff"*16,
    "\x00"*16,
    "\x00"*100,
    "\x00"*1000,
)


openssl_format = "openssl enc %s"
test_format = "./test %s"
str_to_hex = lambda s: "".join(map(lambda c: hex(ord(c)).split("x")[1].rjust(2, "0"), s))
def diff_openssl(input_, key, cipher, iv=None):
  args = "-e %s -K %s" % (cipher, key)
  if iv is not None:
    args += " -iv %s" % iv
  p = Popen(test_format % args, stdin=PIPE, stdout=PIPE, shell=True)
  test_output = p.communicate(input_)[0]
  p = Popen(openssl_format % args, stdin=PIPE, stdout=PIPE, shell=True)
  openssl_output = p.communicate(input_)[0]
  return test_output == openssl_output

# converts an integral value to a 2-character hex representation padded at the
# left with 0s to represent length bits
def num_to_hex(num, bit_len):
  unpadded = hex(num).split("x")[1].rstrip("L")
  hex_length = 2 * bit_len / 8
  return unpadded.rjust(hex_length, "0")

print "=== BEGIN TEST ==="
# constant seed so tests are reproduced
r = Random(0)
get_bits_as_hex = lambda bit_len: num_to_hex(r.getrandbits(bit_len), bit_len)
for mode in modes:
  print "=== BEGIN %s ===" % mode
  for key_len in key_lens:
    print "=== BEGIN %d ===" % key_len
    for input_ in test_cases:
      key_hex = get_bits_as_hex(key_len)
      cipher = cipher_format % (key_len, mode)
      iv_hex = get_hex_bits(32) if mode == "cbc" else None
      if not diff_openssl(input_, key_hex, cipher, iv_hex):
        print "mode:    ", mode
        print "key len: ", key_len
        print "input:   ", str_to_hex(input_)
        print "IV:      ", iv_hex
        fail_fname = "fail%s.in" % cipher
        with open(fail_fname, "wb") as f:
          f.write(input_)
        print "Binary input writtent to file '%s'" % fail_fname
        print "=== FAIL TEST ==="
        sys.exit(1)
    print "=== END %d ===" % key_len
  print "=== END %s ===" % mode
print "=== END TEST ==="
