local luzer = require("luzer")

local args = {
    max_len = 1024,
    print_pcs = 1,
    corpus = "undefined",
    max_total_time = 60,
    print_final_stats = 1,

    -- non-existent flags used for tests
    test_flag = 1,
    test_table = 1,
}
luzer.Fuzz(function() end, nil, args)
