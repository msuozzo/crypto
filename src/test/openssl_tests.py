import sys
from subprocess import Popen, PIPE
from random import Random


key_lens = (128, 192, 256)
modes = ("ecb", "cbc")
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
    "\x00"*10000,
)


openssl_format = "openssl enc %s"
test_format = "./test %s"
str_to_hex = lambda s: "".join(map(lambda c: hex(ord(c)).split("x")[1].rjust(2, "0"), s))
def diff_openssl(input_, key, cipher, iv=None):
  # Build args
  args = "%s -K %s" % (cipher, key_hex)
  if iv_hex is not None:
    args += " -iv %s" % iv_hex
  # Test Encryption
  enc_args = "-e %s" % args
  p = Popen(test_format % enc_args, stdin=PIPE, stdout=PIPE, shell=True)
  test_encrypted = p.communicate(input_)[0]
  p = Popen(openssl_format % enc_args, stdin=PIPE, stdout=PIPE, shell=True)
  openssl_encrypted = p.communicate(input_)[0]
  if not test_encrypted == openssl_encrypted:
    return "encryption", input_
  # Test Decryption
  dec_args = "-d %s" % args
  p = Popen(test_format % dec_args, stdin=PIPE, stdout=PIPE, shell=True)
  test_output = p.communicate(test_encrypted)[0]
  p = Popen(openssl_format % dec_args, stdin=PIPE, stdout=PIPE, shell=True)
  openssl_output = p.communicate(openssl_encrypted)[0]
  if not test_output == openssl_output:
    return "decryption", test_encrypted
  # If no errors occur, return None
  return None, None

# converts an integral value to a 2-character hex representation padded at the
# left with 0s to represent length bits
def num_to_hex(num, bit_len):
  unpadded = hex(num).split("x")[1].rstrip("L")
  hex_length = 2 * bit_len / 8
  return unpadded.rjust(hex_length, "0")

# constant seed so tests are reproduced
r = Random(0)
get_bits_as_hex = lambda bit_len: num_to_hex(r.getrandbits(bit_len), bit_len)
print "=== BEGIN TEST ==="
for mode in modes:
  print "=== BEGIN %s ===" % mode
  for key_len in key_lens:
    print "=== BEGIN %d ===" % key_len
    for input_ in test_cases:
      key_hex = get_bits_as_hex(key_len)
      cipher = cipher_format % (key_len, mode)
      iv_hex = get_bits_as_hex(128) if mode == "cbc" else None
      err_op, err_input = diff_openssl(input_, key_hex, cipher, iv_hex)
      if err_op is not None:
        print "=== FAIL TEST ==="
        print "op     : ", err_op
        print "mode   : ", mode
        print "key len: ", key_len
        print "key    : ", key_hex
        print "input  : ", str_to_hex(err_input)
        print "IV     : ", iv_hex
        fail_fname = "fail%s.in" % cipher
        with open(fail_fname, "wb") as f:
          f.write(err_input)
        print "Binary input written to file '%s'" % fail_fname
        sys.exit(1)
    print "=== END %d ===" % key_len
  print "=== END %s ===" % mode
print "=== END TEST ==="
