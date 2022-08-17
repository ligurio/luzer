local pickle = require('pickle')

local buf = "xxx"
local res = pickle.pack(buf)
assert(buf == pickle.unpack(res))
