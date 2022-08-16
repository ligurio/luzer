local json = require('json')

local body = {}
local buf = json.encode(body)
local res = json.decode(buf)
assert(res == body)
