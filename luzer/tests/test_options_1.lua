local luzer = require("luzer")

local args = {
    corpus = "undefined",
    max_total_time = 1,
}
luzer.Fuzz(function() os.execute('sleep 0.1') end, nil, args)
