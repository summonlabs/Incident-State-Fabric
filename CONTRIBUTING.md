# Contributing to Incident State Fabric

Thanks for your interest in improving Incident State Fabric. This document
covers how to build the library, run the tests, and submit changes.

## Licensing of contributions

By submitting a contribution — a pull request, patch, or any other work
intentionally submitted for inclusion in this project — you agree that your
contribution is licensed under the Apache License, Version 2.0, in accordance
with section 5, "Submission of Contributions", of that license. Unless you explicitly state otherwise, your contribution is provided under
those terms, without any additional terms or conditions.

There is **no Contributor License Agreement (CLA)** to sign and **no copyright
assignment** is required: you retain copyright in your work.

## Building

Requirements:

- Windows x64. CMake refuses to configure on any other platform, because the
  store relies on Win32 locking, atomic replacement, and flush semantics.
- CMake 3.25 or newer.
- A C++20 toolchain: MSVC 19.3x (Visual Studio 2022) is the validated one.

Run the commands below from a Developer Command Prompt (`vcvars64.bat`), or use
the shipped CMake presets.

```bat
cmake -G Ninja -S . -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release
```

## Running the tests

Tests are registered with CTest. Configure and build a build directory first,
then run the suite:

```bat
cmake -G Ninja -S . -B build/debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

The suite includes real independent processes and real abrupt terminations, so
it does real work; let it run to completion. A test that hangs is a defect to
diagnose, not something to wrap in a timeout.

## Code quality expectations

- Target C++20 and standard library facilities only. Avoid compiler-specific
  extensions.
- No new third-party runtime dependencies. Discuss any proposed dependency in
  an issue before writing code that needs it.
- First-party code must compile warning-clean at the project's warning level on
  every supported compiler. Do not silence a warning you have not understood.
- Tests are proof obligations, not optional extras. A change in behavior needs a
  test that fails without the change and passes with it.
- Behavior must be deterministic: no reliance on unordered iteration order,
  wall-clock timing, or unseeded randomness in library code.
- No TODOs, stubs, or placeholder product functionality in merged work. Ship the
  complete behavior or leave it out of the change.
- Keep changes focused; unrelated refactoring belongs in its own pull request.

## Commit messages

- Concise, neutral, and imperative — "Add retry budget to the ingest path".
- Explain why the change is needed, not just what moved.
- No AI attribution of any kind.
- No `Co-authored-by` trailers.
- One logical change per commit where practical.

## Pull request checklist

- [ ] The project configures and builds with CMake 3.25+ on Windows x64 with
      MSVC 19.3x.
- [ ] `ctest` passes locally, including any tests added for this change.
- [ ] New behavior is covered by tests; no placeholders or dead stubs remain.
- [ ] The build is warning-clean for first-party sources.
- [ ] No new third-party runtime dependencies were introduced.
- [ ] Documentation and the NOTICE file are updated where relevant.
- [ ] Commit messages follow the expectations above.
