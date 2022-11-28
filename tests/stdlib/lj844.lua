local tic = os.clock()
for i = 0, 10000 do
  local t = {'A', 'B', 'C'}
  local x = {t[math.random(#t)]}
  table.foreach(x, function(k, v) end)
end
local toc = os.clock()
print(toc - tic)
