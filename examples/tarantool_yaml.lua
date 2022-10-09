local yaml = require("yaml")
local luzer = require("luzer")

--[[
"yaml.cfg"
"yaml.encode_load_metatables"
"yaml.encode_invalid_numbers"
"yaml.encode_use_tostring"
"yaml.decode_max_depth"
"yaml.encode_max_depth"
"yaml.encode_number_precision"
"yaml.encode_sparse_convert"
"yaml.decode_invalid_numbers"
"yaml.encode_error_as_ext"
"yaml.encode_sparse_ratio"
"yaml.encode_invalid_as_nil"
"yaml.encode_sparse_safe"
"yaml.encode_deep_as_nil"
"yaml.decode_save_metatables"
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

local function TestOneInput(buf)
    local ok, res = pcall(yaml.decode, buf)
    if (ok == false) then
        return
    end
    yaml.encode(res)
    buf = nil -- luacheck: no unused
    collectgarbage()
end

local args = {
    dict = "/home/sergeyb/sources/luzer/examples/tarantool_yaml.dict",
    max_len = 2048,
}
luzer.Setup(TestOneInput, nil, args)
luzer.Fuzz()
