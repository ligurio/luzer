local msgpack = require('msgpack')

local body = "\x00"
local buf = msgpack.encode(body)
local res = msgpack.decode(buf)
assert(res == body)
