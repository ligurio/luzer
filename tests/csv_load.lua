local csv = require('csv')

local res = csv.load('a,b,c')
assert(res ~= nil)
