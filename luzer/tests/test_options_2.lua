local luzer = require("luzer")

local args = {
    seed = 12345,
}
luzer.Fuzz(function() end, nil, args)
