--[[
"crypto.cipher_mode"
"crypto.ofb"
"crypto.cfb"
"crypto.ecb"
"crypto.cbc"
"crypto.cipher_algo"
"crypto.none"
"crypto.aes256"
"crypto.des"
"crypto.aes192"
"crypto.aes128"
]]

local luzer = require("luzer")
local crypto = require("crypto")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local _8byte_iv = fdp:consume_string(8)
    local _8byte_pass = fdp:consume_string(8)
    local _16byte_iv = fdp:consume_string(16)
    local _16byte_pass = fdp:consume_string(16)
    local _32byte_iv = fdp:consume_string(32)
    local _32byte_pass = fdp:consume_string(32)

    local b = fdp:consume_string(fdp:remaining_bytes())
    local res
	--local aes128_cbc = crypto.cipher.aes128.cbc
	--res = aes128_cbc.encrypt(b, _16byte_pass, _16byte_iv)
    --assert(buf == aes128_cbc.decrypt(res, _16byte_pass, _16byte_iv))

	--local aes192_cbc = crypto.cipher.aes192.cbc
	--res = aes192_cbc.encrypt(buf, _16byte_pass, _16byte_iv)
    --assert(buf == aes192_cbc.decrypt(res, _16byte_pass, _16byte_iv))

	--local aes256_cbc = crypto.cipher.aes256.cbc
	--res = aes256_cbc.encrypt(buf, _16byte_pass, _16byte_iv)
    --assert(buf == aes256_cbc.decrypt(res, _16byte_pass, _16byte_iv))

	local des_cbc = crypto.cipher.des.cbc
	res = des_cbc.encrypt(b, _8byte_pass, _8byte_iv)
    assert(buf == des_cbc.decrypt(res, _8byte_pass, _8byte_iv))
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local args = {
    only_ascii = 1,
    max_len = 4096,
    dict = "xxx",
}
luzer.Fuzz(TestOneInput, nil, args)
