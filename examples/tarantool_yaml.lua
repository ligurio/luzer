local yaml = require("yaml")
local luzer = require("luzer")

local function TestOneInput(buf, _size)
    local obj = yaml.decode(buf)
    yaml.encode(obj)
end

-- TODO: yaml.dict
local arg1 = {"-max_len=4096", "-max_len=4096", "-only_ascii=1"}
luzer.Setup(arg1, TestOneInput)
luzer.Fuzz()
