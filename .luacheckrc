globals = {
    "box",
    "checkers",
    "package",
}

ignore = {
    -- Accessing an undefined field of a global variable <debug>.
    "143/debug",
    -- Accessing an undefined field of a global variable <os>.
    "143/os",
    -- Accessing an undefined field of a global variable <string>.
    "143/string",
    -- Accessing an undefined field of a global variable <table>.
    "143/table",
    -- Unused argument <self>.
    "212/self",
}

files["tests/tests.lua"] = {
    ignore = {
        -- Shadowing an upvalue.
        "431",
    }
}

files["mulua/mutate.lua"] = {
    ignore = {
        -- Line is too long.
        "631",
    }
}

files["bridges/libfuzzer/libfuzzer_mutator.lua"] = {
    globals = {
        "LLVMFuzzerCustomMutator",
        "LLVMFuzzerMutate",
    },
}

files["bridges/afl-lua/afl_mutator.lua"] = {
    globals = {
        "init",
        "fuzz",
        "fuzz_count",
        "describe",
        "post_process",
        "havoc_mutation",
        "havoc_mutation_probability",
        "queue_get",
        "queue_new_entry",
        "introspection",
        "deinit",
        "init_trim",
        "trim",
        "post_trim",
    },
}

include_files = {
    '.luacheckrc',
    '*.rockspec',
    '**/*.lua',
}

exclude_files = {
    '.rocks',
    'corpus',
    'tests/tap.lua',

    'bridges/afl-lua/minimized',
    'afl-lua',
}
