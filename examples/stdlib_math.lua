--[[

18 – The Mathematical Library
https://www.lua.org/pil/18.html

6.7 – Mathematical Functions
https://www.lua.org/manual/5.3/manual.html#6.7

PUC Rio Lua bugs: https://www.lua.org/bugs.html

LuaJIT bugs:
- https://github.com/LuaJIT/LuaJIT/issues/859
- https://github.com/LuaJIT/LuaJIT/issues/817
- https://github.com/LuaJIT/LuaJIT/issues/817

"math.tan"
"math.cos"
"math.sqrt"
"math.sin"
"math.atan2"
"math.atan"
"math.sinh"
"math.asin"
"math.cosh"
"math.tanh"
"math.acos"

"math.ceil"
"math.pi"
"math.max"
"math.min"
"math.log10"
"math.randomseed"
"math.random"
"math.huge"
"math.ldexp"
"math.floor"
"math.deg"
"math.fmod"
"math.pow"
"math.frexp"
"math.log"
"math.exp"
"math.modf"
"math.rad"
]]

local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local a = fdp:consume_number(1, 1000)

    local sin = math.sin(a)
    local cos = math.cos(a)
    local tan = math.tan(a)

    -- cos α = 1 / sin α
    if sin ~= 0 then
        --print(cos, 1/sin)
        --assert(cos == 1/sin)
    end

    -- tan α = sin α / cos α
    if cos ~= 0 then
        --assert(tan == sin/cos)
    end

    -- cos² α + sin² α = 1
    --assert(cos^2 + sin^2 == 1)

    -- ctan α = 1/tan α
    -- TODO
    return
end

local function TestOneInput_abs(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local a = fdp:consume_number(1, 100)
    local abs = a
    if abs < 0 then
        abs = -abs
    end
    assert(math.abs(a) == abs)

    return
end

local function TestOneInput_sqrt(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local a = fdp:consume_number(1, 100)
    local sqrt = math.sqrt(a)
    assert(sqrt^2 == a)

    -- LuaJIT: "sqrt(x) and x^0.5 not interchangeable"
    -- https://github.com/LuaJIT/LuaJIT/issues/684
    assert(sqrt == a^0.5)

    return
end

-- https://schooltutoring.com/help/properties-of-logarithmic-functions/
-- https://www.chilimath.com/lessons/advanced-algebra/logarithm-rules/
-- https://www.shoreline.edu/math-learning-center/documents/properties-of-logarithms.pdf
local function TestOneInput_log(buf)
    return
end

local function TestOneInput_pow(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local b = fdp:consume_number(1, 100)
    local m = fdp:consume_number(1, 100)
    local n = fdp:consume_number(1, 100)

    local b_pow_m = math.pow(b, m)
    local b_pow_n = math.pow(b, n)

    --assert(b_pow_m * b_pow_n == math.pow(b, m + n))
    --assert(b_pow_m / b_pow_n == math.pow(b, m - n))
    --assert(math.pow(b_pow_m, n) == math.pow(b, m * n))

    return
end

local args = {
    max_len = 4096,
    artifact_prefix = "stdlib_math_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput_sqrt, nil, args)
