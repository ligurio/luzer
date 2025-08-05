files["luzer/tests/test_unit.lua"] = {
    globals = {
        "luzer_custom_mutator",
    },
}

include_files = {
    ".luacheckrc",
    "*.rockspec",
    "**/*.lua",
}

exclude_files = {
    ".rocks",
    "build/",
}
