package.cpath = "./?.so"

local luzer = require("luzer")

local function TestOneInput(buf, _size)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(1)
    if str == "c" then
		assert(nil)
    end
    return
end

local opts = {
    max_len = 4096,
}
luzer.Setup(TestOneInput, nil, opts)
luzer.Fuzz()
