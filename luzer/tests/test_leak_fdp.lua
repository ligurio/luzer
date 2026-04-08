local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    fdp:consume_string(1)
end

local opts = { runs = 100 }
luzer.Fuzz(TestOneInput, nil, opts)
