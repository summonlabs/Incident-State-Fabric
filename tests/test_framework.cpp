// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include "test_framework.h"

#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <string>

namespace {

/// Progress must survive an abrupt process death, so stdout is never buffered.
struct UnbufferedStdout {
  UnbufferedStdout() { std::setvbuf(stdout, nullptr, _IONBF, 0); }
};
const UnbufferedStdout kUnbufferedStdout;

}  // namespace

namespace isftest {
namespace {

const char* g_current_suite = "<none>";
const char* g_current_name = "<none>";
int g_failures_in_test = 0;
int g_total_failures = 0;

[[nodiscard]] bool Matches(const char* suite, const char* name, const std::string& filter) {
  if (filter.empty()) return true;
  const std::string full = std::string(suite) + "." + name;
  return full.find(filter) != std::string::npos;
}

}  // namespace

std::vector<TestCase>& Registry() {
  static std::vector<TestCase> registry;
  return registry;
}

Registrar::Registrar(const char* suite, const char* name, void (*fn)()) {
  Registry().push_back(TestCase{suite, name, fn});
}

void ReportFailure(const char* file, int line, const std::string& message) {
  ++g_failures_in_test;
  ++g_total_failures;
  std::printf("    FAIL %s:%d\n      %s\n", file, line, message.c_str());
  std::fflush(stdout);
}

void FailNow(const char* file, int line, const std::string& message) {
  ReportFailure(file, line, message);
  throw std::runtime_error(message);
}

int RunAll(int argc, char** argv) {
  std::string filter;
  bool list_only = false;
  for (int i = 1; i < argc; ++i) {
    const std::string argument(argv[i]);
    if (argument.rfind("--filter=", 0) == 0) {
      filter = argument.substr(9);
    } else if (argument == "--list") {
      list_only = true;
    }
  }

  std::vector<TestCase> selected;
  for (const TestCase& test : Registry()) {
    if (Matches(test.suite, test.name, filter)) selected.push_back(test);
  }

  if (list_only) {
    for (const TestCase& test : selected) {
      std::printf("%s.%s\n", test.suite, test.name);
    }
    return 0;
  }

  std::printf("running %zu test case(s)", selected.size());
  if (!filter.empty()) std::printf(" matching '%s'", filter.c_str());
  std::printf("\n\n");

  int passed = 0;
  int failed = 0;
  for (const TestCase& test : selected) {
    g_current_suite = test.suite;
    g_current_name = test.name;
    g_failures_in_test = 0;
    std::printf("  run   %s.%s\n", test.suite, test.name);
    try {
      test.fn();
    } catch (const std::exception& error) {
      ReportFailure("<framework>", 0, std::string("unhandled exception: ") + error.what());
    } catch (...) {
      ReportFailure("<framework>", 0, "unhandled exception of an unknown type");
    }
    if (g_failures_in_test == 0) {
      ++passed;
      std::printf("  ok    %s.%s\n", test.suite, test.name);
    } else {
      ++failed;
      std::printf("  FAIL  %s.%s (%d failed check(s))\n", test.suite, test.name,
                  g_failures_in_test);
    }
    std::fflush(stdout);
  }

  std::printf("\n%zu case(s): %d passed, %d failed, %d failed check(s)\n", selected.size(),
              passed, failed, g_total_failures);
  std::fflush(stdout);
  return g_total_failures == 0 ? 0 : 1;
}

}  // namespace isftest

int main(int argc, char** argv) { return isftest::RunAll(argc, argv); }
