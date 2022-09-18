local uri = require('uri')

-- "uri.parse_many"
-- "uri.format"
-- "uri.parse"

local res = uri.parse('%20a@h')
assert(res ~= nil)
