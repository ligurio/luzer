files["mutator/mutator_example.lua"] = {
    globals = {
        "LLVMFuzzerCustomMutator",
        "LLVMFuzzerMutate",

        "luzer_custom_mutator",
    },
}

files["luzer/test.lua"] = {
    globals = {
        "luzer_test_one_input",
        "luzer_custom_mutator",
    },
}

include_files = {
    '.luacheckrc',
    '*.rockspec',
    '**/*.lua',
}

exclude_files = {
    '.rocks',
    'build/',

    'examples/tarantool_datetime.lua',
    'examples/stdlib_string.lua',
    'examples/stdlib_math.lua',
    'trash/',
}
