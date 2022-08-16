local uri = require('uri')

local res = uri.parse('%20a@h')
assert(res ~= nil)
