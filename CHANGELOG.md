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

### Changed

- Disable coverage instrumentation of internal functions (#11).
- Add missed newlines to messages.
- Rename `_VERSION` to a `_LUZER_VERSION`.

### Fixed

- Fix searching Clang RT.
- Stack overflow due to recursive traceback calls.
- Fix a crash due to incorrect `argv` building (#13).
- Fix parsing command-line flags (#23).
