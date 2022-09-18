local digest = require('digest')

--[[
"digest.sha512_hex"
"digest.sha1_hex"
"digest.xxhash64"
"digest.new"
"digest.guava"
"digest.base64_decode"
"digest.sha384"
"digest.xxhash32"
"digest.new"
"digest.sha224"
"digest.aes256cbc"
"digest.encrypt"
"digest.decrypt"
"digest.urandom"
"digest.sha256_hex"
"digest.sha512"
"digest.crc32_update"
"digest.sha256"
"digest.md4"
"digest.sha1"
"digest.sha384_hex"
"digest.md4_hex"
"digest.murmur"
"digest.new"
"digest.default_seed"
"digest.pbkdf2_hex"
"digest.base64_encode"
"digest.crc32"
"digest.crc_begin"
"digest.new"
"digest.pbkdf2"
"digest.md5_hex"
"digest.sha224_hex"
"digest.md5"
]]

local buf, res
buf = "xxx"
res = digest.base64_encode(buf)
assert(buf == digest.base64_decode(res))

buf = "xxx"
res = digest.aes256cbc.encrypt(buf)
assert(buf == digest.aes256cbc.decrypt(res))
