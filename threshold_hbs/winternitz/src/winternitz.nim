import std/math
import std/random
import std/sequtils
import nimcrypto

type WinternitzKeyPair = object
  privateKey: ptr UncheckedArray[byte]
  publicKey: ptr UncheckedArray[byte]

proc generate_random_bytes (address: ptr seq[byte], length: int) =
  randomize()

  for i in 0..<length:
    address[].add(byte(rand(0..255)))

# TODO: optimize this hash_bytes by avoiding appending to the sequence.
proc hash_bytes (source: ptr seq[byte], dest: ptr seq[byte], length: int) =
  for i in countup(0, length - 1, 32):
    let chunkSize = min(32, length - i)
    let chunk = source[][i..<i+chunkSize]
    let hash: seq[byte] = sha256.digest(chunk).data.toSeq()
    dest[].add(hash)

proc generate_keypair (n: int, w: int): WinternitzKeyPair {. exportc, dynlib .} =
  let a = n div w
  let pow_w = 1 shl w
  let c = int(ceil(log2(float(a) * (float(pow_w) - 1.0))/float(w)))

  # Type annotations because I have to be aware that these are unsafe, raw pointers rather than the reference-counted, 'smart' `ptr` type of pointers.
  let rawPrivateKey: pointer = alloc0((n div 8) * (a + c) * pow_w)
  let rawPublicKey: pointer = alloc0((n div 8) * (a + c))

  # Note: for performance reasons, I have transposed the secret key matrix to ensure that the key
  # generation algorithm uses contiguous memory access patterns. 
  var privateKey = newSeq[seq[byte]](pow_w)
  var publicKey: seq[byte] = @[]
  generate_random_bytes(addr privateKey[0], (n div 8) * (a + c))

  for i in 1..<pow_w:
    privateKey[i] = @[]
    hash_bytes(addr privateKey[i - 1], addr privateKey[i], (a + c) * (n div 8))

  hash_bytes(addr privateKey[pow_w - 1], addr publicKey, (a + c) * (n div 8))

  copyMem(rawPublicKey, addr publicKey, (a + c) * (n div 8))

  for i in 0..<pow_w:
    for j in 0..<a + c:
      let offset = cast[uint]((j * pow_w + i) * (n div 8))
      let dest: pointer = cast[pointer](cast[uint](rawPrivateKey) + offset)
      copyMem(dest, addr privateKey[i][j], n div 8)

  result = WinternitzKeyPair(
    privateKey: cast[ptr UncheckedArray[byte]](rawPrivateKey),
    publicKey: cast[ptr UncheckedArray[byte]](rawPublicKey),
  )

# This is where we encounter some fuckery
# We are NOT assuming that w is cleanly divisible in this array; where is the challenge there?
proc split (message: seq[byte], w: int): seq[byte] =
  result = @[]
  if w < 8:
    for i in countup(0, message.len * 8, w):
      let current_byte_index = i div 8
      let current_bit = i mod 8

      let requires_next_byte = w < (8 - current_bit)

      if requires_next_byte:
        let remainder = (8 - (current_bit + w))
        assert remainder < 0

        let mask_1 = byte(255 shr current_bit)
        let mask_2 = byte(255 shl (8 + remainder))

        let value1 = (message[current_byte_index] and mask_1) shl abs(remainder)
        let value2 = (message[current_byte_index + 1] and mask_2) shr (8 + remainder)
        result.add(value1 and value2)
      else:
        let remainder = (8 - (current_bit + w))
        let mask = byte((255 shr current_bit) and (255 shl remainder))
        let value = (message[current_byte_index] and mask) shr remainder
        result.add(value)
  else:
    discard


type WinternitzSignature = distinct ptr UncheckedArray[byte]

proc sign (message: seq[byte], secret_key: seq[seq[byte]], n: int, w: int): WinternitzSignature {. exportc, dynlib .} =
  let a = n div w
  let pow_w = 1 shl w

  var c_sum = a * (pow_w - 1)
  discard