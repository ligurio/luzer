math.randomseed(os.clock())
for i = 1, 120 do
   local val = math.random(10)
   if val < 0 or val > 10 then
      local kind = "none"
      if val < 0 then kind = "less" end
      if val > 10 then kind = "more" end
      print(val, kind)
   end
end
