// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef ISF_RESULT_H
#define ISF_RESULT_H

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

namespace isf {

/// Every way an operation can fail. Values are stable and public.
enum class ErrorCode : std::uint32_t {
  Ok = 0,

  // Request shape
  InvalidArgument = 1,
  NotFound = 2,
  AlreadyExists = 3,
  Conflict = 4,
  LimitExceeded = 5,
  Unsupported = 6,

  // Domain rules
  IllegalTransition = 20,
  GateUnsatisfied = 21,
  NotCurrentEvidence = 22,
  ReopenLimitReached = 23,
  DuplicateIdentity = 24,

  // Authority
  Unauthorized = 40,
  AuthorityRevoked = 41,
  AuthorityUnknown = 42,
  StaleControlEpoch = 43,
  StaleRevision = 44,
  IdempotencyConflict = 45,

  // Arithmetic
  Overflow = 60,

  // Store
  StoreLocked = 80,
  StoreCorrupt = 81,
  StoreIncompatible = 82,
  StoreIoError = 83,
  StoreClosed = 84,
  IntegrityFailure = 85,
  UnsafePath = 86,
  ResourceExhausted = 87,

  InternalError = 120,
};

[[nodiscard]] const char* ToString(ErrorCode code) noexcept;

/// A status is either success or a stable code plus a deterministic message.
/// Messages never contain addresses, timestamps, or thread identifiers, so two
/// runs that reach the same decision produce byte-identical messages.
class Status {
 public:
  Status() noexcept = default;

  [[nodiscard]] static Status Ok() noexcept { return Status{}; }
  [[nodiscard]] static Status Error(ErrorCode code, std::string message) {
    Status s;
    s.code_ = code;
    s.message_ = std::move(message);
    return s;
  }

  [[nodiscard]] bool ok() const noexcept { return code_ == ErrorCode::Ok; }
  [[nodiscard]] ErrorCode code() const noexcept { return code_; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }

  [[nodiscard]] std::string ToString() const {
    std::string out = isf::ToString(code_);
    if (!message_.empty()) {
      out += ": ";
      out += message_;
    }
    return out;
  }

 private:
  ErrorCode code_ = ErrorCode::Ok;
  std::string message_;
};

/// Either a value or a Status. Never both, never neither.
template <typename T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Result(Status status) : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool ok() const noexcept { return value_.has_value(); }
  [[nodiscard]] const Status& status() const noexcept { return status_; }

  T& value() & { return *value_; }
  const T& value() const& { return *value_; }
  T&& value() && { return std::move(*value_); }

  [[nodiscard]] T& operator*() & { return *value_; }
  [[nodiscard]] const T& operator*() const& { return *value_; }
  [[nodiscard]] T* operator->() { return &*value_; }
  [[nodiscard]] const T* operator->() const { return &*value_; }

 private:
  std::optional<T> value_;
  Status status_;
};

}  // namespace isf

#endif  // ISF_RESULT_H
