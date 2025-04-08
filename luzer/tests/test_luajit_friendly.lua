local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local numbers = fdp:consume_numbers(0, 2*10^6, 10)
    for _, n in ipairs(numbers) do
        if n == 100500 then
            assert("Bingo!")
        end
    end
end

local args = {
    print_pcs = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
