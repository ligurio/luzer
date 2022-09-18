-- box.sql.execute('analyze t')
-- https://github.com/tarantool/tarantool/issues/3866
-- https://github.com/tarantool/tarantool/issues/3861

--[[
box.cfg{}
sql = "SELECT 1 "
for i = 1, 106 do
    sql = sql .. string.format("+ %s ", i)
    end
    box.sql.execute(sql)
]]
