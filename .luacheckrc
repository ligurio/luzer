files["mutator/mutator_example.lua"] = {
    globals = {
        "LLVMFuzzerCustomMutator",
        "LLVMFuzzerMutate",
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

    'trash/',
}
