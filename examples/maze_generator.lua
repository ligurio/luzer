-- Maze generator in Lua
-- Joe Wingbermuehle 2013-10-06
-- source: https://raw.githubusercontent.com/joewing/maze/master/maze.lua
-- https://en.wikipedia.org/wiki/Maze_generation_algorithm

-- Create an empty maze array.
local function init_maze(width, height)
   local result = {}
   for y = 0, height - 1 do
      for x = 0, width - 1 do
         result[y * width + x] = 1
      end
      result[y * width + 0] = 0
      result[y * width + width - 1] = 0
   end
   for x = 0, width - 1 do
      result[0 * width + x] = 0
      result[(height - 1) * width + x] = 0
   end
   return result
end

-- Show a maze.
local function show_maze(maze, width, height)
   for y = 0, height - 1 do
      for x = 0, width - 1 do
         if maze[y * width + x] == 0 then
            io.write("  ")
         else
            io.write("[]")
         end
      end
      io.write("\n")
   end
end

-- Carve the maze starting at x, y.
local function carve_maze(maze, width, height, x, y)
   local r = math.random(0, 3)
   maze[y * width + x] = 0
   for i = 0, 3 do
      local d = (i + r) % 4
      local dx = 0
      local dy = 0
      if d == 0 then
         dx = 1
      elseif d == 1 then
         dx = -1
      elseif d == 2 then
         dy = 1
      else
         dy = -1
      end
      local nx = x + dx
      local ny = y + dy
      local nx2 = nx + dx
      local ny2 = ny + dy
      if maze[ny * width + nx] == 1 then
         if maze[ny2 * width + nx2] == 1 then
            maze[ny * width + nx] = 0
            carve_maze(maze, width, height, nx2, ny2)
         end
      end
   end

    -- Make entrance.
	local entrance_pos = width + 2
    maze[entrance_pos] = 0

    -- Make exit.
	local exit_pos = (height - 2) * width + width - 3
    maze[exit_pos] = 0

    return entrance_pos, exit_pos
end

-- The size of the maze (must be odd).
local width = 39
local height = 23

-- Initialize random number generator.
math.randomseed(os.time())

if arg[0] == "maze_generator.lua" then
    -- Generate and display a random maze.
    local maze = init_maze(width, height)
    carve_maze(maze, width, height, 2, 2)
    show_maze(maze, width, height)
end

return {
    init = init_maze,
	carve = carve_maze,
	show = show_maze,
}
