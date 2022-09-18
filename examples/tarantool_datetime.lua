--[[
    https://web.archive.org/web/20150906092420/http://www.cs.tau.ac.il/~nachumd/horror.html
    https://web.archive.org/web/20150908004245/http://www.merlyn.demon.co.uk/critdate.htm
    https://en.wikipedia.org/wiki/Epoch#Notable_epoch_dates_in_computing
    https://en.wikipedia.org/wiki/Time_formatting_and_storage_bugs
    https://en.wikipedia.org/wiki/Leap_year_problem
    https://medium.com/grandcentrix/property-based-test-driven-development-in-elixir-49cc70c7c3c4
    https://groups.google.com/g/comp.dcom.telecom/c/Qq0lwZYG_fI

    https://cs.opensource.google/go/go/+/refs/tags/go1.18.2:src/time/zoneinfo_test.go
    https://github.com/dateutil/dateutil/blob/master/tests/test_tz.py

"datetime.new"
"datetime.parse_date"
"datetime.now"
"datetime.parse"
"datetime.is_datetime"
"datetime.interval"
"datetime.new"

]]

local math = require('math')
local datetime = require('datetime')
local log = require('log')

math.randomseed(os.time())

local MIN_DATE_YEAR = -5879610
local MAX_DATE_YEAR = 5879611

local now_dt = datetime.now

local function random_fmt()
	-- Field descriptors.
  	local desc = {
       		'%a',
		'%A',
       		'%b',
		'%B',
		'%h',
       		'%c',
       		'%C',
       		'%d',
		'%e',
       		'%D',
       		'%H',
       		'%I',
       		'%j',
       		'%m',
       		'%M',
       		'%n',
       		'%p',
       		'%r',
       		'%R',
       		'%S',
       		'%t',
       		'%T',
       		'%U',
       		'%w',
       		'%W',
       		'%x',
       		'%X',
       		'%y',
       		'%Y',
	}
	local n = math.random(1, #desc)
	local fmt = ''
	for i = 1, n do
            local idx = math.random(1, n)
            fmt = fmt .. desc[idx]
	end

	return fmt
end

local function new_dt()
    local d = 0
    while d == 0 do
        d = math.random(-1, math.random(1, 31))
    end

    return {
        -- FIXME: only one of nsec, usec or msecs may be defined simultaneously.
        -- TODO: usec
        -- TODO: msec
        nsec      = math.random(0, 1000000000),
        sec       = math.random(0, 60),
        min       = math.random(0, 59),
        hour      = math.random(0, 23),
        day       = d,
        month     = math.random(1, 12),
        year      = math.random(MIN_DATE_YEAR, MAX_DATE_YEAR),
        tzoffset  = math.random(-720, 840),
        tz        = 'MSK'  -- FIXME: support tz names (datetime.TZ)
    }
end

-- Minimum supported date - -5879610-06-22.
local min_dt = {
    nsec      = 0,
    sec       = 0,
    min       = 0,
    hour      = 0,
    day       = -1,
    month     = 1,
    year      = MIN_DATE_YEAR,
    tzoffset  = -720,
    tz        = 'MSK'  -- FIXME: support tz names (datetime.TZ)
}

-- Maximum supported date - 5879611-07-11.
local max_dt = {
    nsec      = 1000000000,
    sec       = 60,
    min       = 59,
    hour      = 23,
    day       = 31,
    month     = 12,
    year      = MAX_DATE_YEAR,
    tzoffset  = 840,
    tz        = 'MSK'  -- FIXME: support tz names (datetime.TZ)
}

-- https://docs.microsoft.com/en-us/office/troubleshoot/excel/determine-a-leap-year
local function isLeapYear(year)
    -- bool leap = st.wYear % 4 == 0 && (st.wYear % 100 != 0 || st.wYear % 400 == 0); 
    if year%4 ~= 0 then
        return false
    elseif year%100 ~= 0 then
        return true
    elseif year%400 ~= 0 then
        return false
    else
        return true
    end
end

local function getYear(is_leap)
    while true do
        local y = math.random(MIN_DATE_YEAR, MAX_DATE_YEAR)
        if isLeapYear(y) == is_leap then
            return y
        end
    end
end

-- Property: B - (B - A) == A
-- https://github.com/tarantool/tarantool/issues/7145
local dt = new_dt()
local new = datetime.new()
local sub_dt = new - dt
local add_dt = sub_dt + dt
-- BUG: assert(add_dt == new, '(A - B) + B != A')

-- Property: A - A == B - B
-- https://github.com/tarantool/tarantool/issues/7144
local dt = datetime.new(new_dt())
local now = now_dt()
-- BUG: assert(dt - dt == now - now, 'A - A != B - B')

-- Property: datetime.new(dt) == datetime.new():set(dt)
local dt = new_dt()
assert(datetime.new(dt) == datetime.new():set(dt), 'new(dt) != new():set(dt)')

-- Property: dt == datetime.new(dt):totable()
local dt = new_dt()
table.equals(dt, datetime.new():totable())
table.equals(dt, datetime.new())

-- Property: datetime.parse(tostring(dt)):format() == tostring(dt)
local dt = datetime.new(new_dt())
local dt_iso8601 = datetime.parse(tostring(dt), {format = 'iso8601'}):format()
assert(dt_iso8601 == tostring(dt), ('Parse roundtrip with iso8601 %s'):format(tostring(dt)))
local dt_rfc3339 = datetime.parse(tostring(dt), {format = 'rfc3339'}):format()
assert(dt_rfc3339 == tostring(dt), ('Parse roundtrip with rfc3339 %s'):format(tostring(dt)))

-- Property: Formatted datetime is the same as produced by os.date().
local dt = datetime.new(new_dt())
local fmt = random_fmt()
-- Seems os.date() does not support negative epoch.
if dt.epoch > 0 then
    assert(os.date(fmt, dt.epoch) == dt:format(fmt), ('os.date("%s", %d) != dt:format("%s")'):format(fmt, dt.epoch, fmt))
end

-- Property: in leap year last day in February is 29.
local dt = datetime.new(new_dt())
dt:set({
    day = 01,
    month = 02,
    year = getYear(true),
})
assert(dt:set({ day = -1}).day == 29, ("Last day in %s (leap year) is not a 29"):format(tostring(dt)))

-- Property: in non-leap year last day in February is 28.
local dt = datetime.new(new_dt())
dt:set({
    day = 01,
    month = 02,
    year = getYear(false),
})
assert(dt:set({ day = -1 }).day == 28, ("Last day in %s (non-leap year) is not a 28"):format(tostring(dt)))

-- Property: 28.02.YYYY + 1 year == 28.02.(YYYY + 1), where YYYY is a non-leap year.
local dt = datetime.new(new_dt())
dt:set({
    year = getYear(false),
    month = 02,
    day = 28,
})
dt_plus_1y = dt:add({year = 1})
-- https://www.quora.com/When-did-using-a-leap-year-start
if dt_plus_1y.year > 1584 then
    assert(dt_plus_1y.day == 28, ('Non-leap year: 28.02.YYYY + 1Y != 28.02.(YYYY + 1): %s + 1y != %s '):format(dt, dt_plus_1y))
end

-- Property: 29.02.YYYY + 1 year == 28.02.(YYYY + 1), where YYYY is a leap year. 
local dt = datetime.new(new_dt())
dt:set({
    year = getYear(true),
    month = 02,
    day = 29,
})
dt_plus_1y = dt:add({year = 1})
-- https://www.quora.com/When-did-using-a-leap-year-start
if dt_plus_1y.year > 1584 then
    assert(dt_plus_1y.day == 28, ('Leap year: 29.02.YYYY + 1Y != 28.02.(YYYY + 1): %s + 1y != %s'):format(dt, dt_plus_1y))
end

-- Property: 31.03.YYYY + 1 month == 30.04.YYYY
local dt = datetime.new(new_dt())
dt:set({
    month = 03,
    day = 31,
})
dt_plus_1m = dt
dt_plus_1m:add({month = 1})
assert(dt_plus_1m.day == 30, ('31.03.YYYY + 1m != 30.04.YYYY: %s + 1m != %s'):format(dt, dt_plus_1m))
assert(dt_plus_1m.month == 04, ('31.03.YYYY + 1m != 30.04.YYYY: %s + 1m != %s'):format(dt, dt_plus_1m))

-- Property: 31.12.YYYY + 1 day == 01.01.(YYYY + 1)
-- "February 29 is not the only day affected by the leap year. Another very
-- important date is December 31, because it is the 366th day of the year and
-- many applications mistakenly hard-code a year as 365 days."
-- Source: https://azure.microsoft.com/en-us/blog/is-your-code-ready-for-the-leap-year/
local dt = datetime.new(new_dt())
dt:set({
    day = 01,
    month = 12,
})
dt = dt:set({ day = -1 })
assert(dt.day == 31)
dt = dt:add({ day = 1})
-- BUG: assert(dt.day == 1, ('31 Dec + 1 day != 1 Jan (%s)'):format(dt))

-- Property: Difference of datetimes with leap and non-leap years is 1 second.
local leap_year = getYear(true) 
local non_leap_year = getYear(false) 
local dt1 = datetime.new({ year = leap_year })
local dt2 = datetime.new({ year = non_leap_year })
-- local diff = datetime.new():set({ year = leap_year - non_leap_year, sec = 1})
-- TODO: assert(dt1 - dt2 == single_sec, ('%s - %s != 1 sec (%s)'):format(dt1, dt2, dt1 - dt2))

-- Property: Timezone changes when DST applied.
-- Property: The day before Saturday is always Friday.
-- Property: 29.02.YYYY + 1 day == 01.03.(YYYY + 1), where YYYY is a leap year. 
-- Property: 28.02.YYYY + 1 day == 01.03.(YYYY + 1), where YYYY is a non-leap year. 

-- Прибавление месяцев к времени даёт ту же дату в другом месяце, кроме
-- случаев, когда в итоговом месяце меньше дней нежели в исходном. В этом
-- случае получаем последний день.
-- 31 января + 1 месяц = 28 или 29 февраля
-- 30 января + 1 месяц = 28 или 29 февраля
-- 29 февраля + 1 месяц = 29 марта
-- 31 марта + 1 месяц = 30 апреля

-- Прибавление месяцев к последнему дню месяца (требует обсуждения). При
-- прибавлении месяцев к последнему дню месяца надо получать последний день
-- месяца.
-- 31 января + 1 месяц  = 28 или 29 февраля
-- 29 февраля + 1 месяц = 31 марта
-- 31 марта + 1 месяц = 30 апреля
-- 30 апреля + 1 месяц = 31 мая
-- 28 февраля 2001 + 1 месяц = 28 марта 2001
-- 28 февраля 2004 + 1 месяц = 28 марта 2004


--[[
--
--На прошлой неделе мы выпустили новую версию Tarantool - 2.10. Эта версия
--примечательна тем, что в ней появилась поддержка нового типа для работы с
--датой и временем - datetime. В этом типе таится много нюансов: високосные
--года и секунда, таймзоны, DST (перевод часов на зимнее и летнее время). Из-за
--високосной секунды может быть время 23:59:60 и даже 23:59:61, 29 февраля
--бывает только в високосный год, причем иногда переход на DST может
--происходить два раза в год. С этим типом связано какое-то невероятное
--количество ошибок. Я даже писал заметку про баг в Excel, там до сих пор для
--совместимости с предыдущими версиями 1900-й год считается високосным, хотя он
--не високосный. Одно время Microsoft выпускала музыкальный плеер Zune и там
--тоже была проблема расчёта високосного года - 31 декабря в високосный год все
--плееры выключились.
--
--С таким количеством деталей идея применить тестирование с помощью свойств
--кажется очень заманчивой - генерировать тестовые примеры на всём диапазоне и
--проверять соответствие спецификации. Но я пересмотрел тесты для реализации
--datetime в Python и Go и всё тестирование там строится вокруг конкретных
--примеров. Хотя нет, вру, автор Hypothesis писал в своём блоге про тестирование
--парсинга даты из строки с помощью roundtrip - если напечатать дату в заданном
--формате в строку и распарсить её с тем же форматом, то результат должен
--совпасть с первоначальной датой. Но roundtrip это слишком просто, хотя тот же
--автор Hypothesis нашел с таким тестом проблему в базовой библиотеке Python.
--
-- Несколько типов багов: переполнение, неверная арифметика, парсинг дат из строк.
-- Those that lead to error conditions, such as exceptions, error return codes,
-- uninitialized variables, or endless loops
-- Those that lead to incorrect data, such as off-by-one problems in range
-- queries or aggregation
--
--]]
