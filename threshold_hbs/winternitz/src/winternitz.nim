import std/math
import std/random
import std/sequtils
import std/algorithm
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

  copyMem(rawPublicKey, addr publicKey[0], (a + c) * (n div 8))

  for i in 0..<pow_w:
    for j in 0..<a + c:
      let offset = cast[uint]((j * pow_w + i) * (n div 8))
      let dest: pointer = cast[pointer](cast[uint](rawPrivateKey) + offset)
      copyMem(dest, addr privateKey[i][j * (n div 8)], n div 8)

  result = WinternitzKeyPair(
    privateKey: cast[ptr UncheckedArray[byte]](rawPrivateKey),
    publicKey: cast[ptr UncheckedArray[byte]](rawPublicKey),
  )

# This is where we encounter some fuckery
# We are NOT assuming that w is cleanly divisible in this array; where is the challenge there?
proc split (message: seq[byte], w: int): seq[int64] =
  result = @[]
  if w < 8:
    for i in countup(0, message.len * 8 - 1, w):
      let current_byte_index = i div 8
      let current_bit = i mod 8

      let requires_next_byte = w > (8 - current_bit)
      let remainder = (8 - (current_bit + w))

      if requires_next_byte:
        if current_byte_index == message.len - 1:
          let mask = byte(255 shr current_bit)
          let value = message[current_byte_index] and mask
          result.add(int64(value))
        else:
          let mask_1 = byte(255 shr current_bit)
          let mask_2 = byte(255 shl (8 + remainder))

          let value1 = (message[current_byte_index] and mask_1) shl abs(remainder)
          let value2 = (message[current_byte_index + 1] and mask_2) shr (8 + remainder)

          result.add(int64(value1) or int64(value2))
      else:
        let mask = byte((255 shr current_bit) and (255 shl remainder))
        let value = (message[current_byte_index] and mask) shr remainder
        result.add(int64(value))
  else:
    for i in countup(0, message.len * 8 - 1, w):
      var value: int64 = 0
      var bits_collected = 0
      var bit_pos = i

      while bits_collected < w:
        let byte_idx = bit_pos div 8
        if byte_idx >= message.len:
          break
        let bit_in_byte = bit_pos mod 8
        let available = 8 - bit_in_byte
        let take = min(available, w - bits_collected)
        let shift = available - take
        let mask = byte((1 shl take) - 1)
        let extracted = int64((message[byte_idx] shr shift) and mask)
        value = (value shl take) or extracted
        bits_collected += take
        bit_pos += take

      result.add(value)

proc to_bytes (value: int64, c: int): seq[byte] =
  result = newSeq[byte]()

  for i in 0..<c:
    if i < 8:
      let shift = i * 8;
      result.add(byte(((0xFF shr shift) and value) shr shift))
    else:
      result.add(byte(0))

  result.reverse()


type WinternitzSignature = distinct ptr UncheckedArray[byte]

proc sign (message: seq[byte], secret_key: seq[seq[byte]], n: int, w: int): WinternitzSignature =
  let a = n div w
  let pow_w = 1 shl w
  let c = int(ceil(log2(float(a) * (float(pow_w) - 1.0))/float(w)))

  var b: seq[int64] = split(message, w)
  var c_sum = a * (pow_w - 1) - sum(b)
  b.add(split(to_bytes(c_sum, c), w))

  let z_raw: pointer = alloc0((a + c) * (n div 8))

  for i in 0..<a+c:
    let idx = b[i]
    let offset = cast[uint](i * (n div 8))
    let dest: pointer = cast[pointer](cast[uint](z_raw) + offset)
    copyMem(dest, addr secret_key[i][idx * (n div 8)], n div 8)

  result = cast[WinternitzSignature](z_raw)

proc sign (message: ptr UncheckedArray[byte], secret_key: ptr UncheckedArray[byte], n: int, w: int): ptr UncheckedArray[byte] {. exportc, dynlib .} =
  let a = n div w
  let pow_w = 1 shl w
  let c = int(ceil(log2(float(a) * (float(pow_w) - 1.0))/float(w)))
  let block_size = n div 8

  # Convert message to seq[byte]
  var msg_seq = newSeq[byte](block_size)
  copyMem(addr msg_seq[0], message, block_size)

  # Convert secret_key to seq[seq[byte]]
  # Raw layout: chain j at offset j * pow_w * block_size, contiguous across depths
  var sk_seq = newSeq[seq[byte]](a + c)
  for j in 0..<a + c:
    sk_seq[j] = newSeq[byte](pow_w * block_size)
    copyMem(addr sk_seq[j][0], cast[pointer](cast[uint](secret_key) + cast[uint](j * pow_w * block_size)), pow_w * block_size)

  result = cast[ptr UncheckedArray[byte]](sign(msg_seq, sk_seq, n, w))

proc verify (message: seq[byte], signature: seq[byte], public_key: seq[byte], n: int, w: int): bool =
  let a = n div w
  let pow_w = 1 shl w
  let c = int(ceil(log2(float(a) * (float(pow_w) - 1.0))/float(w)))
  let block_size = n div 8

  var b: seq[int64] = split(message, w)
  var c_sum = a * (pow_w - 1) - sum(b)
  b.add(split(to_bytes(c_sum, c), w))

  var computed_pk: seq[byte] = @[]

  for i in 0..<a+c:
    var value: seq[byte] = signature[i * block_size..<(i + 1) * block_size]
    for _ in b[i]..<pow_w:
      var hashed: seq[byte] = @[]
      hash_bytes(addr value, addr hashed, block_size)
      value = hashed
    computed_pk.add(value)

  return computed_pk == public_key

proc verify (message: ptr UncheckedArray[byte], signature: ptr UncheckedArray[byte], public_key: ptr UncheckedArray[byte], n: int, w: int): bool {. exportc, dynlib .} =
  let a = n div w
  let pow_w = 1 shl w
  let c = int(ceil(log2(float(a) * (float(pow_w) - 1.0))/float(w)))
  let block_size = n div 8

  var msg_seq = newSeq[byte](block_size)
  copyMem(addr msg_seq[0], message, block_size)

  var sig_seq = newSeq[byte]((a + c) * block_size)
  copyMem(addr sig_seq[0], signature, (a + c) * block_size)

  var pk_seq = newSeq[byte]((a + c) * block_size)
  copyMem(addr pk_seq[0], public_key, (a + c) * block_size)

  result = verify(msg_seq, sig_seq, pk_seq, n, w)