// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// A small, dependency-free proof harness. Tests are proof obligations: a failed
// check is a defect, never a flake.

#ifndef ISF_TEST_FRAMEWORK_H
#define ISF_TEST_FRAMEWORK_H

#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "isf/result.h"
#include "isf/types.h"

namespace isftest {

struct TestCase {
  const char* suite;
  const char* name;
  void (*fn)();
};

std::vector<TestCase>& Registry();

void ReportFailure(const char* file, int line, const std::string& message);

/// Reports a failure and throws, so that a helper which must return a value can
/// still fail the test cleanly. The runner catches the exception and marks the
/// case failed.
[[noreturn]] void FailNow(const char* file, int line, const std::string& message);

class Registrar {
 public:
  Registrar(const char* suite, const char* name, void (*fn)());
};

/// Runs every registered test, honouring --filter=<substring> and --list.
int RunAll(int argc, char** argv);

// ---------------------------------------------------------------------------
// Value rendering for failure messages
// ---------------------------------------------------------------------------

template <typename T>
std::string Repr(const T& value) {
  if constexpr (std::is_enum_v<T>) {
    return std::string(isf::ToString(value));
  } else if constexpr (std::is_same_v<T, bool>) {
    return value ? "true" : "false";
  } else if constexpr (std::is_arithmetic_v<T>) {
    return std::to_string(value);
  } else if constexpr (std::is_convertible_v<const T&, std::string_view>) {
    return std::string(std::string_view(value));
  } else {
    return "<value>";
  }
}

template <typename Tag>
std::string Repr(const isf::StrongId<Tag>& id) {
  return std::to_string(id.value());
}

inline std::string Repr(const isf::ControlEpoch& epoch) { return std::to_string(epoch.value); }

inline std::string Repr(const isf::IdempotencyKey& key) {
  return std::to_string(key.hi) + ":" + std::to_string(key.lo);
}

inline std::string Repr(const isf::Status& status) { return status.ToString(); }

template <typename T>
std::string Repr(const std::vector<T>& values) {
  std::string out = "[";
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i != 0) out += ", ";
    out += Repr(values[i]);
  }
  out += "]";
  return out;
}

}  // namespace isftest

#define ISF_TEST(Suite, Name)                                                     \
  static void Suite##_##Name##_body();                                            \
  static const ::isftest::Registrar Suite##_##Name##_registrar(#Suite, #Name,     \
                                                               &Suite##_##Name##_body); \
  static void Suite##_##Name##_body()

#define ISF_CHECK(condition)                                                      \
  do {                                                                            \
    if (!(condition)) {                                                           \
      ::isftest::ReportFailure(__FILE__, __LINE__,                                \
                               std::string("check failed: ") + #condition);       \
    }                                                                             \
  } while (false)

// The operands are copied, never bound by reference: an operand such as
// result.value().field is a subobject of a temporary that dies at the end of
// this full expression, and a reference to it would dangle.
#define ISF_CHECK_EQ(left, right)                                                 \
  do {                                                                            \
    const auto isf_left = (left);                                                 \
    const auto isf_right = (right);                                               \
    if (!(isf_left == isf_right)) {                                               \
      ::isftest::ReportFailure(__FILE__, __LINE__,                                \
                               std::string("expected ") + #left + " == " + #right + \
                                   "\n      left:  " + ::isftest::Repr(isf_left) +  \
                                   "\n      right: " + ::isftest::Repr(isf_right)); \
    }                                                                             \
  } while (false)

#define ISF_REQUIRE(condition)                                                    \
  do {                                                                            \
    if (!(condition)) {                                                           \
      ::isftest::ReportFailure(__FILE__, __LINE__,                                \
                               std::string("requirement failed: ") + #condition); \
      return;                                                                     \
    }                                                                             \
  } while (false)

/// Binds \c name to the value of a successful Result, failing the test and
/// returning when the Result is an error.
#define ISF_MUST_SUCCEED(name, expression)                                        \
  auto name##_result = (expression);                                              \
  if (!name##_result.ok()) {                                                      \
    ::isftest::ReportFailure(__FILE__, __LINE__,                                  \
                             std::string("expected success from ") + #expression + \
                                 " but got " + ::isftest::Repr(name##_result.status())); \
    return;                                                                       \
  }                                                                               \
  auto& name = name##_result.value()

/// Fails and unwinds when a Result is an error. Unlike ISF_REQUIRE this is
/// usable inside helpers that return a value.
#define ISF_MUST(expression)                                                      \
  do {                                                                            \
    auto isf_must_result = (expression);                                          \
    if (!isf_must_result.ok()) {                                                  \
      ::isftest::FailNow(__FILE__, __LINE__,                                      \
                         std::string("expected success from ") + #expression +    \
                             " but got " + isf_must_result.status().ToString());  \
    }                                                                             \
  } while (false)

/// Asserts that a Result fails with a specific code.
#define ISF_EXPECT_ERROR(expression, expected_code)                               \
  do {                                                                            \
    auto isf_result = (expression);                                               \
    if (isf_result.ok()) {                                                        \
      ::isftest::ReportFailure(__FILE__, __LINE__,                                \
                               std::string("expected ") + #expected_code +        \
                                   " from " + #expression + " but it succeeded"); \
    } else if (isf_result.status().code() != (expected_code)) {                    \
      ::isftest::ReportFailure(                                                    \
          __FILE__, __LINE__,                                                      \
          std::string("expected ") + #expected_code + " from " + #expression +     \
              " but got " + isf_result.status().ToString());                       \
    }                                                                             \
  } while (false)

#endif  // ISF_TEST_FRAMEWORK_H
