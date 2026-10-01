// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.
//
// Windows implementation. This build is validated on Windows x64 only; the
// library refuses to configure anywhere else rather than shipping an
// unvalidated port.

#ifndef _WIN32
#error "Incident State Fabric is implemented and validated for Windows only."
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "detail/platform.h"

#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <string>
#include <system_error>

#include "detail/format.h"

namespace isf::detail::platform {
namespace {

[[nodiscard]] std::string LastErrorMessage(const char* operation) {
  const DWORD code = ::GetLastError();
  std::string message = operation;
  message += " failed with Win32 error ";
  message += std::to_string(static_cast<unsigned long>(code));
  return message;
}

[[nodiscard]] Status IoError(const char* operation) {
  return Status::Error(ErrorCode::StoreIoError, LastErrorMessage(operation));
}

/// Backslash-Backslash-Question-Backslash prefix, which lifts the MAX_PATH limit
/// and disables the device-name post-processing that would otherwise alias a
/// component named NUL to a device.
[[nodiscard]] std::wstring ToExtended(const std::wstring& absolute) {
  const std::wstring prefix = std::wstring(2, L'\\') + L'?' + L'\\';
  if (absolute.rfind(prefix, 0) == 0) return absolute;
  const std::wstring unc = std::wstring(2, L'\\');
  if (absolute.rfind(unc, 0) == 0) {
    return prefix + L"UNC" + L'\\' + absolute.substr(2);
  }
  return prefix + absolute;
}

[[nodiscard]] bool EndsWithDotOrSpace(const std::wstring& component) {
  if (component.empty()) return false;
  const wchar_t last = component.back();
  return last == L'.' || last == L' ';
}

[[nodiscard]] bool HasTrailingSeparator(const std::wstring& path) {
  if (path.size() <= 3) return false;
  const wchar_t last = path.back();
  return last == L'\\' || last == L'/';
}

[[nodiscard]] std::vector<std::wstring> SplitComponents(const std::wstring& path) {
  std::vector<std::wstring> components;
  std::wstring current;
  for (const wchar_t unit : path) {
    if (unit == L'\\' || unit == L'/') {
      if (!current.empty()) {
        components.push_back(current);
        current.clear();
      }
    } else {
      current.push_back(unit);
    }
  }
  if (!current.empty()) components.push_back(current);
  return components;
}

/// True when the component is a reserved MS-DOS device name. Compared as UTF-8
/// after conversion so that non-ASCII components are never misinterpreted.
[[nodiscard]] bool IsReservedComponent(const std::wstring& component) {
  auto narrow = WideToUtf8(component);
  if (!narrow.ok()) return false;
  return IsReservedDeviceName(narrow.value());
}

[[nodiscard]] Result<std::wstring> CurrentDirectory() {
  const DWORD needed = ::GetCurrentDirectoryW(0, nullptr);
  if (needed == 0) return IoError("GetCurrentDirectoryW");
  std::wstring buffer(static_cast<std::size_t>(needed), L'\0');
  const DWORD written = ::GetCurrentDirectoryW(needed, buffer.data());
  if (written == 0 || written >= needed) return IoError("GetCurrentDirectoryW");
  buffer.resize(static_cast<std::size_t>(written));
  return buffer;
}

[[nodiscard]] /// Reads an environment variable without the deprecated CRT accessor.
[[nodiscard]] std::string ReadEnvironment(const char* name) {
  char* buffer = nullptr;
  std::size_t size = 0;
  if (::_dupenv_s(&buffer, &size, name) != 0 || buffer == nullptr) return std::string();
  std::string value(buffer);
  std::free(buffer);
  return value;
}

[[nodiscard]] Status SeekTo(HANDLE handle, std::uint64_t offset) {
  LARGE_INTEGER position{};
  position.QuadPart = static_cast<LONGLONG>(offset);
  if (::SetFilePointerEx(handle, position, nullptr, FILE_BEGIN) == 0) {
    return IoError("SetFilePointerEx");
  }
  return Status::Ok();
}

}  // namespace

Result<std::wstring> Utf8ToWide(const std::string& text) {
  if (text.empty()) return std::wstring();
  const int needed = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                           static_cast<int>(text.size()), nullptr, 0);
  if (needed <= 0) {
    return Status::Error(ErrorCode::InvalidArgument, "text is not well-formed UTF-8");
  }
  std::wstring wide(static_cast<std::size_t>(needed), L'\0');
  const int written = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                            static_cast<int>(text.size()), wide.data(), needed);
  if (written != needed) {
    return Status::Error(ErrorCode::InvalidArgument,
                         "UTF-8 conversion produced an unexpected length");
  }
  for (const wchar_t unit : wide) {
    if (unit >= 0xd800 && unit <= 0xdfff) {
      return Status::Error(ErrorCode::InvalidArgument,
                           "text contains an unpaired UTF-16 surrogate");
    }
  }
  return wide;
}

Result<std::string> WideToUtf8(const std::wstring& text) {
  if (text.empty()) return std::string();
  const int needed = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
  if (needed <= 0) return IoError("WideCharToMultiByte");
  std::string narrow(static_cast<std::size_t>(needed), '\0');
  const int written = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                            narrow.data(), needed, nullptr, nullptr);
  if (written != needed) return IoError("WideCharToMultiByte");
  return narrow;
}

Result<std::wstring> ResolveStorePath(const std::string& utf8_path) {
  if (utf8_path.empty()) {
    return Status::Error(ErrorCode::InvalidArgument, "store path is empty");
  }
  if (utf8_path.find('\0') != std::string::npos) {
    return Status::Error(ErrorCode::InvalidArgument, "store path contains an embedded NUL");
  }
  auto wide = Utf8ToWide(utf8_path);
  if (!wide.ok()) return wide.status();
  std::wstring path = std::move(wide).value();
  if (HasTrailingSeparator(path)) {
    return Status::Error(ErrorCode::UnsafePath, "store path ends with a directory separator");
  }

  // Refuse extended-length, device, and UNC paths outright: a store path must be
  // an ordinary drive-letter path so that reparse and aliasing behaviour stays
  // predictable.
  const std::wstring unc = std::wstring(2, L'\\');
  if (path.rfind(unc, 0) == 0) {
    return Status::Error(ErrorCode::UnsafePath,
                         "store path must not be a UNC, device, or extended-length path");
  }
  const bool absolute = path.size() >= 3 && path[1] == L':' &&
                        (path[2] == L'\\' || path[2] == L'/');
  if (!absolute) {
    auto cwd = CurrentDirectory();
    if (!cwd.ok()) return cwd.status();
    std::wstring combined = cwd.value();
    combined.push_back(L'\\');
    combined += path;
    path = std::move(combined);
  }

  const wchar_t drive = path[0];
  const bool drive_ok = (drive >= L'A' && drive <= L'Z') || (drive >= L'a' && drive <= L'z');
  if (!drive_ok || path[1] != L':') {
    return Status::Error(ErrorCode::UnsafePath, "store path has an invalid drive letter");
  }

  std::wstring normalised;
  normalised.push_back(static_cast<wchar_t>(::towupper(drive)));
  normalised += L":";
  normalised.push_back(L'\\');

  const std::vector<std::wstring> components = SplitComponents(path.substr(3));
  if (components.empty()) {
    return Status::Error(ErrorCode::UnsafePath,
                         "store path must name a directory below the drive root");
  }
  for (const std::wstring& component : components) {
    if (component == L".") continue;
    if (component == L"..") {
      return Status::Error(ErrorCode::UnsafePath, "store path must not contain parent references");
    }
    if (EndsWithDotOrSpace(component)) {
      return Status::Error(ErrorCode::UnsafePath,
                           "store path contains a component ending in a dot or space");
    }
    if (IsReservedComponent(component)) {
      return Status::Error(ErrorCode::UnsafePath, "store path contains a reserved device name");
    }
    if (normalised.back() != L'\\') normalised.push_back(L'\\');
    normalised += component;
  }
  return ToExtended(normalised);
}

std::wstring StripExtendedPrefix(const std::wstring& path) {
  const std::wstring prefix = std::wstring(2, L'\\') + L'?' + L'\\';
  if (path.rfind(prefix, 0) != 0) return path;
  const std::wstring rest = path.substr(prefix.size());
  const std::wstring unc_prefix = L"UNC" + std::wstring(1, L'\\');
  if (rest.rfind(unc_prefix, 0) == 0) {
    return std::wstring(2, L'\\') + rest.substr(unc_prefix.size());
  }
  return rest;
}

Result<bool> ExistsReparsePoint(const std::wstring& path) {
  const DWORD attributes = ::GetFileAttributesW(path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    const DWORD code = ::GetLastError();
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) return false;
    return Status::Error(ErrorCode::StoreIoError, LastErrorMessage("GetFileAttributesW"));
  }
  return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

bool PathExists(const std::wstring& path) {
  return ::GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool IsDirectory(const std::wstring& path) {
  const DWORD attributes = ::GetFileAttributesW(path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) return false;
  return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

Status CreateDirectories(const std::wstring& path) {
  std::error_code error;
  const std::filesystem::path fs_path(path);
  std::filesystem::create_directories(fs_path, error);
  if (error && !std::filesystem::is_directory(fs_path)) {
    return Status::Error(ErrorCode::StoreIoError, "could not create directory: " + error.message());
  }
  return Status::Ok();
}

FileLock::~FileLock() { Release(); }

FileLock::FileLock(FileLock&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }

FileLock& FileLock::operator=(FileLock&& other) noexcept {
  if (this != &other) {
    Release();
    handle_ = other.handle_;
    other.handle_ = nullptr;
  }
  return *this;
}

Status FileLock::Acquire(const std::wstring& path) {
  Release();
  HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) return IoError("CreateFileW(lock)");

  OVERLAPPED overlapped{};
  if (::LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0,
                   &overlapped) == 0) {
    const DWORD code = ::GetLastError();
    ::CloseHandle(handle);
    if (code == ERROR_LOCK_VIOLATION || code == ERROR_IO_PENDING) {
      return Status::Error(ErrorCode::StoreLocked,
                           "another process currently owns mutation authority for this store");
    }
    return Status::Error(ErrorCode::StoreIoError, LastErrorMessage("LockFileEx"));
  }
  handle_ = handle;
  return Status::Ok();
}

void FileLock::Release() {
  if (handle_ == nullptr) return;
  HANDLE handle = static_cast<HANDLE>(handle_);
  OVERLAPPED overlapped{};
  ::UnlockFileEx(handle, 0, 1, 0, &overlapped);
  ::CloseHandle(handle);
  handle_ = nullptr;
}

FileHandle::~FileHandle() { Close(); }

FileHandle::FileHandle(FileHandle&& other) noexcept : handle_(other.handle_) {
  other.handle_ = nullptr;
}

FileHandle& FileHandle::operator=(FileHandle&& other) noexcept {
  if (this != &other) {
    Close();
    handle_ = other.handle_;
    other.handle_ = nullptr;
  }
  return *this;
}

Status FileHandle::Open(const std::wstring& path, bool create_if_missing) {
  Close();
  const DWORD disposition = create_if_missing ? OPEN_ALWAYS : OPEN_EXISTING;
  HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, disposition,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD code = ::GetLastError();
    if (!create_if_missing && (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)) {
      return Status::Error(ErrorCode::StoreCorrupt, "required store file is missing");
    }
    return IoError("CreateFileW");
  }
  handle_ = handle;
  return Status::Ok();
}

void FileHandle::Close() {
  if (handle_ == nullptr) return;
  ::CloseHandle(static_cast<HANDLE>(handle_));
  handle_ = nullptr;
}

Status FileHandle::WriteAt(std::uint64_t offset, const void* data, std::size_t length) {
  if (handle_ == nullptr) return Status::Error(ErrorCode::StoreClosed, "file handle is not open");
  Status status = SeekTo(static_cast<HANDLE>(handle_), offset);
  if (!status.ok()) return status;
  const auto* bytes = static_cast<const std::byte*>(data);
  std::size_t written_total = 0;
  while (written_total < length) {
    DWORD written = 0;
    const DWORD chunk =
        static_cast<DWORD>(std::min<std::size_t>(length - written_total, 1u << 20));
    if (::WriteFile(static_cast<HANDLE>(handle_), bytes + written_total, chunk, &written,
                    nullptr) == 0) {
      return IoError("WriteFile");
    }
    if (written == 0) return Status::Error(ErrorCode::StoreIoError, "WriteFile wrote zero bytes");
    written_total += written;
  }
  return Status::Ok();
}

Status FileHandle::Flush() {
  if (handle_ == nullptr) return Status::Error(ErrorCode::StoreClosed, "file handle is not open");
  if (::FlushFileBuffers(static_cast<HANDLE>(handle_)) == 0) return IoError("FlushFileBuffers");
  return Status::Ok();
}

Status FileHandle::Truncate(std::uint64_t length) {
  if (handle_ == nullptr) return Status::Error(ErrorCode::StoreClosed, "file handle is not open");
  Status status = SeekTo(static_cast<HANDLE>(handle_), length);
  if (!status.ok()) return status;
  if (::SetEndOfFile(static_cast<HANDLE>(handle_)) == 0) return IoError("SetEndOfFile");
  return Status::Ok();
}

Result<std::uint64_t> FileHandle::Size() {
  if (handle_ == nullptr) return Status::Error(ErrorCode::StoreClosed, "file handle is not open");
  LARGE_INTEGER size{};
  if (::GetFileSizeEx(static_cast<HANDLE>(handle_), &size) == 0) return IoError("GetFileSizeEx");
  return static_cast<std::uint64_t>(size.QuadPart);
}

Result<std::vector<std::byte>> ReadFileRange(const std::wstring& path, std::uint64_t offset,
                                             std::uint64_t length) {
  HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) return IoError("CreateFileW(read)");
  if (offset > 0) {
    const Status seek = SeekTo(handle, offset);
    if (!seek.ok()) {
      ::CloseHandle(handle);
      return seek;
    }
  }

  std::vector<std::byte> buffer(static_cast<std::size_t>(length));
  std::uint64_t read_total = 0;
  while (read_total < length) {
    DWORD read = 0;
    const DWORD chunk = static_cast<DWORD>(std::min<std::uint64_t>(length - read_total, 1u << 20));
    if (::ReadFile(handle, buffer.data() + read_total, chunk, &read, nullptr) == 0) {
      const Status failure = IoError("ReadFile");
      ::CloseHandle(handle);
      return failure;
    }
    if (read == 0) {
      ::CloseHandle(handle);
      return Status::Error(ErrorCode::StoreCorrupt, "file ended before its declared length");
    }
    read_total += read;
  }
  ::CloseHandle(handle);
  return buffer;
}

Result<std::vector<std::byte>> ReadFileBounded(const std::wstring& path, std::uint64_t maximum) {
  FileHandle handle;
  Status status = handle.Open(path, false);
  if (!status.ok()) return status;
  auto size = handle.Size();
  if (!size.ok()) return size.status();
  const std::uint64_t length = size.value();
  handle.Close();
  if (length > maximum) {
    return Status::Error(ErrorCode::ResourceExhausted,
                         "file is larger than the permitted maximum of " +
                             std::to_string(maximum) + " bytes");
  }
  return ReadFileRange(path, 0, length);
}

Status PublishAtomically(const std::wstring& staging_path, const std::wstring& target_path,
                         const std::vector<std::byte>& bytes) {
  FileHandle staging;
  Status status = staging.Open(staging_path, true);
  if (!status.ok()) return status;
  status = staging.Truncate(0);
  if (!status.ok()) return status;
  if (!bytes.empty()) {
    status = staging.WriteAt(0, bytes.data(), bytes.size());
    if (!status.ok()) return status;
  }
  status = staging.Flush();
  if (!status.ok()) return status;
  staging.Close();

  // Read the staged bytes back through an independent handle before publishing.
  auto verify = ReadFileRange(staging_path, 0, bytes.size());
  if (!verify.ok()) return verify.status();
  if (verify.value() != bytes) {
    return Status::Error(ErrorCode::IntegrityFailure,
                         "staged file read-back does not match the bytes that were written");
  }

  if (::MoveFileExW(staging_path.c_str(), target_path.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    return IoError("MoveFileExW(publish)");
  }
  return Status::Ok();
}

Status DeleteFileQuietly(const std::wstring& path) {
  if (::DeleteFileW(path.c_str()) != 0) return Status::Ok();
  const DWORD code = ::GetLastError();
  if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) return Status::Ok();
  return Status::Error(ErrorCode::StoreIoError, LastErrorMessage("DeleteFileW"));
}

Result<std::vector<std::string>> ListDirectoryNames(const std::wstring& directory) {
  std::vector<std::string> names;
  const std::wstring pattern = directory + L"\\*";
  WIN32_FIND_DATAW data{};
  HANDLE handle = ::FindFirstFileW(pattern.c_str(), &data);
  if (handle == INVALID_HANDLE_VALUE) {
    const DWORD code = ::GetLastError();
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) return names;
    return IoError("FindFirstFileW");
  }
  do {
    const std::wstring name(data.cFileName);
    if (name == L"." || name == L"..") continue;
    auto narrow = WideToUtf8(name);
    if (!narrow.ok()) continue;
    names.push_back(std::move(narrow).value());
  } while (::FindNextFileW(handle, &data) != 0);
  ::FindClose(handle);
  std::sort(names.begin(), names.end());
  return names;
}

Result<std::vector<std::string>> ListSegmentFileNames(const std::wstring& directory) {
  auto names = ListDirectoryNames(directory);
  if (!names.ok()) return names.status();
  std::vector<std::string> segments;
  for (const std::string& name : names.value()) {
    std::uint32_t index = 0;
    if (ParseSegmentFileName(name, index)) segments.push_back(name);
  }
  return segments;
}

void CrashPoint(const char* phase, std::uint64_t generation) {
  const std::string text = ReadEnvironment("ISF_CRASH_POINT");
  if (text.empty()) return;
  const std::size_t separator = text.find(':');
  const std::string wanted_phase =
      separator == std::string::npos ? text : text.substr(0, separator);
  if (wanted_phase != phase) return;
  if (separator != std::string::npos) {
    const std::string generation_text = text.substr(separator + 1);
    if (!generation_text.empty()) {
      std::uint64_t wanted = 0;
      for (const char raw : generation_text) {
        if (raw < '0' || raw > '9') return;
        wanted = wanted * 10u + static_cast<std::uint64_t>(raw - '0');
      }
      if (wanted != generation) return;
    }
  }
  // Terminate immediately: no destructors, no atexit handlers, no CRT cleanup.
  // This is the deterministic crash boundary used by the durability proofs.
  ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(70));
  std::_Exit(70);
}

}  // namespace isf::detail::platform
