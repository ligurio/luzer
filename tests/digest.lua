local digest = require('digest')

local buf = "xxx"
local res = digest.base64_encode(buf)
assert(buf == digest.base64_decode(res))

local buf = "xxx"
local res = digest.aes256cbc.encrypt(buf)
assert(buf == digest.aes256cbc.decrypt(res))
