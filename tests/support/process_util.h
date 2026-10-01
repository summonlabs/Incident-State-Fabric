// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Real independent OS-process control for the lock, crash, and restart proofs.

#ifndef ISF_TEST_PROCESS_UTIL_H
#define ISF_TEST_PROCESS_UTIL_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace isftest {

struct ChildProcess {
  void* process = nullptr;
  void* thread = nullptr;
  unsigned long id = 0;
};

/// Directory holding the running test executable.
[[nodiscard]] std::string TestExecutableDirectory();

/// Absolute path of the isfctl helper, which is built next to the test binary.
[[nodiscard]] std::string CtlExecutable();

[[nodiscard]] bool Spawn(const std::string& executable,
                         const std::vector<std::string>& arguments,
                         const std::vector<std::pair<std::string, std::string>>& environment,
                         ChildProcess& out);

/// Blocks until the child ends. There is no deadline: a child that never
/// finishes is a defect to diagnose, not a flake to time out.
void WaitForExit(ChildProcess& child, unsigned long& exit_code);

/// Terminates the child abruptly. The operating system reclaims its handles,
/// which is exactly what an unexpected process death looks like.
void TerminateNow(ChildProcess& child, unsigned long exit_code);

void CloseProcess(ChildProcess& child);

[[nodiscard]] std::string ReadTextFile(const std::string& path);
[[nodiscard]] bool WriteTextFile(const std::string& path, const std::string& text);

/// Blocks until the file exists with non-empty content.
[[nodiscard]] std::string WaitForFileText(const std::string& path);

/// Blocks until the file reports "generation=<n>" with n >= target. Returns the
/// last content read.
[[nodiscard]] std::string WaitForGeneration(const std::string& path, std::uint64_t target);

[[nodiscard]] std::uint64_t ParseUintField(const std::string& text, const std::string& field);

}  // namespace isftest

#endif  // ISF_TEST_PROCESS_UTIL_H
