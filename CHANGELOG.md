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

### Changed

- Disable coverage instrumentation of internal functions (#11).
- Add missed newlines to messages.

### Fixed

- Fix searching Clang RT.
- Stack overflow due to recursive traceback calls.
