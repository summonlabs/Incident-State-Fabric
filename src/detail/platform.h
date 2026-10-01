// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// The only file in the library that talks to the operating system. Everything
// above it works on canonical byte buffers and value types.

#ifndef ISF_DETAIL_PLATFORM_H
#define ISF_DETAIL_PLATFORM_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "isf/result.h"

namespace isf::detail::platform {

/// Outcome of a durability-relevant file operation.
struct FileError {
  ErrorCode code = ErrorCode::StoreIoError;
  std::string message;
};

/// Converts UTF-8 text to a wide string, rejecting malformed input rather than
/// substituting replacement characters. Fails with InvalidArgument.
[[nodiscard]] Result<std::wstring> Utf8ToWide(const std::string& text);

/// Converts a well-formed wide string back to UTF-8.
[[nodiscard]] Result<std::string> WideToUtf8(const std::wstring& text);

/// Absolute, lexically normalised, extended-length form of a store path.
/// Rejects trailing-dot/space components, reserved device names, embedded NUL,
/// and paths that are still relative after normalisation.
[[nodiscard]] Result<std::wstring> ResolveStorePath(const std::string& utf8_path);

/// Removes the extended-length prefix, producing a path that ResolveStorePath
/// accepts again. Reporting an extended path would make it unusable as input.
[[nodiscard]] std::wstring StripExtendedPrefix(const std::wstring& path);

/// True when the path exists and carries FILE_ATTRIBUTE_REPARSE_POINT.
[[nodiscard]] Result<bool> ExistsReparsePoint(const std::wstring& path);
[[nodiscard]] bool PathExists(const std::wstring& path);
[[nodiscard]] bool IsDirectory(const std::wstring& path);

[[nodiscard]] Status CreateDirectories(const std::wstring& path);

/// A kernel-owned exclusive lock on a file. The lock is released by the
/// operating system when the owning process ends for any reason, including an
/// abrupt termination, which is what makes successor fencing meaningful.
class FileLock {
 public:
  FileLock() = default;
  ~FileLock();
  FileLock(const FileLock&) = delete;
  FileLock& operator=(const FileLock&) = delete;
  FileLock(FileLock&& other) noexcept;
  FileLock& operator=(FileLock&& other) noexcept;

  [[nodiscard]] Status Acquire(const std::wstring& path);
  void Release();

 private:
  void* handle_ = nullptr;
};

/// Reads a whole file into memory, refusing anything larger than \p maximum.
[[nodiscard]] Result<std::vector<std::byte>> ReadFileBounded(const std::wstring& path,
                                                             std::uint64_t maximum);

/// Reads exactly \p length bytes starting at \p offset. Fails if the file is
/// shorter than requested.
[[nodiscard]] Result<std::vector<std::byte>> ReadFileRange(const std::wstring& path,
                                                           std::uint64_t offset,
                                                           std::uint64_t length);

/// Opens (creating if requested) a file for append-style writes. The caller
/// owns the handle through \c FileHandle.
class FileHandle {
 public:
  FileHandle() = default;
  ~FileHandle();
  FileHandle(const FileHandle&) = delete;
  FileHandle& operator=(const FileHandle&) = delete;
  FileHandle(FileHandle&& other) noexcept;
  FileHandle& operator=(FileHandle&& other) noexcept;

  [[nodiscard]] Status Open(const std::wstring& path, bool create_if_missing);
  void Close();
  [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr; }

  [[nodiscard]] Status WriteAt(std::uint64_t offset, const void* data, std::size_t length);
  [[nodiscard]] Status Flush();
  [[nodiscard]] Status Truncate(std::uint64_t length);
  [[nodiscard]] Result<std::uint64_t> Size();

 private:
  void* handle_ = nullptr;
};

/// Stages bytes in \p staging_path (create, write, flush, read back, verify),
/// then atomically replaces \p target_path. The replace is the commit point.
[[nodiscard]] Status PublishAtomically(const std::wstring& staging_path,
                                       const std::wstring& target_path,
                                       const std::vector<std::byte>& bytes);

[[nodiscard]] Status DeleteFileQuietly(const std::wstring& path);

/// Lists the segment file names directly inside \p directory. Returns bare
/// names in ascending order.
[[nodiscard]] Result<std::vector<std::string>> ListDirectoryNames(const std::wstring& directory);

[[nodiscard]] Result<std::vector<std::string>> ListSegmentFileNames(const std::wstring& directory);

/// Deterministic crash injection used by the crash-consistency proofs. Reads
/// ISF_CRASH_POINT of the form "<phase>:<generation>" and terminates the process
/// immediately without running destructors when both match. Never returns in
/// that case.
void CrashPoint(const char* phase, std::uint64_t generation);

}  // namespace isf::detail::platform

#endif  // ISF_DETAIL_PLATFORM_H
