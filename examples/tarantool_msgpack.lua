--[[
"msgpack.decode_array_header"
"msgpack.encode"
"msgpack.array_mt"
"msgpack.__serialize"
"msgpack.seq"
"msgpack.__newindex"
"msgpack.map_mt"
"msgpack.__serialize"
"msgpack.map"
"msgpack.__newindex"
"msgpack.object_from_raw"
"msgpack.new"
"msgpack.is_object"
"msgpack.cfg"
"msgpack.encode_load_metatables"
"msgpack.encode_invalid_numbers"
"msgpack.encode_use_tostring"
"msgpack.decode_max_depth"
"msgpack.encode_max_depth"
"msgpack.encode_number_precision"
"msgpack.encode_sparse_convert"
"msgpack.decode_invalid_numbers"
"msgpack.encode_error_as_ext"
"msgpack.encode_sparse_ratio"
"msgpack.encode_invalid_as_nil"
"msgpack.encode_sparse_safe"
"msgpack.encode_deep_as_nil"
"msgpack.decode_save_metatables"
"msgpack.object"
"msgpack.ibuf_decode"
"msgpack.decode"
"msgpack.decode_map_header"
"msgpack.decode_unchecked"
]]

local msgpack = require("msgpack")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ok, res = pcall(msgpack.decode, buf)
    if ok == true then
        local b
        ok, b = pcall(msgpack.encode, res)
        --assert(ok == true)
        --assert(#b == #buf)
        --assert(b == buf)
    end
end

local args = {
    -- corpus = "~/sources/luzer/build/luzer/msgpack.dict",
    max_len = 4096,
}
luzer.Setup(TestOneInput, nil, args)
luzer.Fuzz()
