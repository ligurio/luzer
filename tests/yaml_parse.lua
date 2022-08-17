local yaml = require('yaml')

local res = yaml.decode(string.rep('{', 6200))
assert(res ~= nil)
