local digest = require('digest')

local buf, res
buf = "xxx"
res = digest.base64_encode(buf)
assert(buf == digest.base64_decode(res))

buf = "xxx"
res = digest.aes256cbc.encrypt(buf)
assert(buf == digest.aes256cbc.decrypt(res))
