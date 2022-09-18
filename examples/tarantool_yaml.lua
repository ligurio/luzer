local yaml = require("yaml")
local luzer = require("luzer")

--[[
"yaml.cfg"
"yaml.encode_load_metatables"
"yaml.true"
"yaml.encode_invalid_numbers"
"yaml.true"
"yaml.encode_use_tostring"
"yaml.false"
"yaml.decode_max_depth"
"yaml.encode_max_depth"
"yaml.encode_number_precision"
"yaml.encode_sparse_convert"
"yaml.true"
"yaml.decode_invalid_numbers"
"yaml.true"
"yaml.encode_error_as_ext"
"yaml.true"
"yaml.encode_sparse_ratio"
"yaml.encode_invalid_as_nil"
"yaml.false"
"yaml.encode_sparse_safe"
"yaml.encode_deep_as_nil"
"yaml.false"
"yaml.decode_save_metatables"
"yaml.true"
"yaml.NULL"
"yaml.new"
"yaml.array_mt"
"yaml.__serialize"
"yaml.seq"
"yaml.__newindex"
"yaml.decode"
"yaml.map_mt"
"yaml.__serialize"
"yaml.map"
"yaml.__newindex"
"yaml.encode"
]]

local function TestOneInput(buf, _size)
    local obj = yaml.decode(buf)
    yaml.encode(obj)
end

-- TODO: yaml.dict
local arg1 = {"-max_len=4096", "-max_len=4096", "-only_ascii=1"}
luzer.Setup(arg1, TestOneInput)
luzer.Fuzz()
