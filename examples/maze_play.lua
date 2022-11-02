-- https://asciinema.org/a/486297

local maze_generator = require("maze_generator")

local clear_screen = function()
    io.write("\027[H\027[2J")
end

local function do_step(maze, height, width, cur_pos, direction, exit_pos)
    local new_pos = 1
    for y = 0, height - 1 do
        for x = 0, width - 1 do
            if maze[y * width + x] == 0 then
                return "NEW STEP"
            else
                return cur_pos
            end
        end
    end
end

-- The size of the maze (must be odd).
local width = 39
local height = 23

-- Initialize random number generator.
math.randomseed(os.time())

-- Generate and display a random maze.
local maze = maze_generator.init(width, height)
local entrance_pos, exit_pos = maze_generator.carve(maze, width, height, 2, 2)

local cur_pos = entrance_pos
maze_generator.show(maze, width, height, cur_pos)

-- Walking maze.
-- repeat op = io.read() until op:match "%p"
while true do
    print("Enter direction (N, W, S, E): ")
    local direction = io.read(2)
    clear_screen()
	direction = direction:gsub("\n[^\n]*$", "")
    if direction ~= "N" and
       direction ~= "W" and
       direction ~= "S" and
       direction ~= "E" then
        print(("Wrong direction (%s)!"):format(direction))
    end
    --cur_pos = do_step(maze, height, width, cur_pos, direction, exit_pos)
    if cur_pos == exit_pos then
	    print("SUCCESS!")
	    break
    else
        maze_generator.show(maze, width, height, cur_pos)
    end
end
