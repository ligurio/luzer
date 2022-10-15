local luzer = require("luzer")
local popen = require("popen")

local TARANTOOL_PATH = arg[-1]

local function TestOneInput(buf)
    local ph = popen.new({ TARANTOOL_PATH }, {
        shell = true,
        setsid = true,
        stdout = popen.opts.INHERIT,
        stderr = popen.opts.INHERIT,
        stdin = popen.opts.PIPE,
    })
	if not ph then
	    return
	end
    assert(ph)
    ph:write(buf .. "\n")
    ph:shutdown({ stdin = true })
    ph:wait()
    ph:close()
end

if arg[1] then
    local fh = io.open(arg[1])
    local testcase = fh:read("*all")
    TestOneInput(testcase)
    os.exit()
end

local args = {
    max_len = 4096,
}
luzer.Fuzz(TestOneInput, nil, args)
