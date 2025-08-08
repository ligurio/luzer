# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Integration with libFuzzer's `LLVMFuzzerTestOneInput()`.
- Integration with libFuzzer's `LLVMFuzzerCustomMutator()`.
- Integration with libFuzzer's `FuzzedDataProvider`.
- Examples with tests.
- Documentation with usecases, API etc.
- Support command-line options.
- Method `oneof()` in FuzzedDataProvider.
- Support LuaJIT library in a build system (#46).
- Support LuaJIT-friendly mode (#22).
- Support LuaCov.
- Support Address and UndefinedBehaviour sanitizers.
- Support for building on macOS ARM64.

### Changed

- Disable coverage instrumentation of internal functions (#11).
- Add missed newlines to messages.
- Rename `_VERSION` to a `_LUZER_VERSION`.
- Use `lua_Number` in FDP methods `consume_number()` and
  `consume_numbers()` instead `double`.
- Method `oneof()` in FuzzedDataProvider returns an item's index
  as a second value.

### Fixed

- Fix searching Clang RT.
- Stack overflow due to recursive traceback calls.
- Fix a crash due to incorrect `argv` building (#13).
- Fix parsing command-line flags (#23).
- Multiple initialization of the FDP metatable.
- Building the project using luarocks (#4).
- Installation using luarocks (#27).
- Running with libFuzzer option `-jobs` (#32).
- Integer overflow in `consume_integer()` and `consume_integers()`
  functions (#29).
- Segmentation fault on tracing Lua source code (#18).
- Arguments order in `consume_integers()` and `consume_numbers()` (#44).
- Arguments checking in `Fuzz()` (#41).
- A memory leak in a Lua-based implementation of `TestOneInput()`.
- An initial buffer size in FuzzedDataProvider.
