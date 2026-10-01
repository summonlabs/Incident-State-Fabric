// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#ifndef _WIN32
#error "The proof suite targets Windows."
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "support/process_util.h"

#include <windows.h>

#include <fstream>
#include <sstream>

namespace isftest {
namespace {

[[nodiscard]] std::wstring Widen(const std::string& text) {
  if (text.empty()) return std::wstring();
  const int needed = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                           nullptr, 0);
  std::wstring wide(static_cast<std::size_t>(needed), L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(),
                        needed);
  return wide;
}

[[nodiscard]] std::string Narrow(const std::wstring& text) {
  if (text.empty()) return std::string();
  const int needed = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
  std::string narrow(static_cast<std::size_t>(needed), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), narrow.data(),
                        needed, nullptr, nullptr);
  return narrow;
}

[[nodiscard]] std::string QuoteArgument(const std::string& argument) {
  if (argument.find_first_of(" \t\"") == std::string::npos) return argument;
  std::string quoted = "\"";
  for (const char raw : argument) {
    if (raw == '"') quoted += "\\\"";
    else quoted.push_back(raw);
  }
  quoted += "\"";
  return quoted;
}

}  // namespace

std::string TestExecutableDirectory() {
  wchar_t buffer[MAX_PATH * 4] = {};
  const DWORD written = ::GetModuleFileNameW(nullptr, buffer, static_cast<DWORD>(std::size(buffer)));
  if (written == 0) return std::string();
  std::wstring path(buffer, written);
  const std::size_t separator = path.find_last_of(L"\\/");
  if (separator == std::wstring::npos) return std::string();
  return Narrow(path.substr(0, separator));
}

std::string CtlExecutable() {
#ifdef ISF_CTL_EXECUTABLE
  return ISF_CTL_EXECUTABLE;
#else
  return TestExecutableDirectory() + "\\isfctl.exe";
#endif
}

bool Spawn(const std::string& executable, const std::vector<std::string>& arguments,
           const std::vector<std::pair<std::string, std::string>>& environment,
           ChildProcess& out) {
  std::string command_line = QuoteArgument(executable);
  for (const std::string& argument : arguments) {
    command_line += " ";
    command_line += QuoteArgument(argument);
  }
  std::wstring wide_command = Widen(command_line);
  std::vector<wchar_t> mutable_command(wide_command.begin(), wide_command.end());
  mutable_command.push_back(L'\0');

  std::wstring environment_block;
  if (!environment.empty()) {
    std::vector<std::pair<std::string, std::string>> merged;
    LPWCH existing = ::GetEnvironmentStringsW();
    if (existing != nullptr) {
      for (const wchar_t* entry = existing; *entry != L'\0'; entry += std::wcslen(entry) + 1) {
        const std::wstring wide(entry);
        const std::size_t equals = wide.find(L'=');
        if (equals == std::wstring::npos) continue;
        merged.emplace_back(Narrow(wide.substr(0, equals)), Narrow(wide.substr(equals + 1)));
      }
      ::FreeEnvironmentStringsW(existing);
    }
    for (const auto& override_entry : environment) {
      bool replaced = false;
      for (auto& candidate : merged) {
        if (candidate.first == override_entry.first) {
          candidate.second = override_entry.second;
          replaced = true;
          break;
        }
      }
      if (!replaced) merged.push_back(override_entry);
    }
    for (const auto& entry : merged) {
      environment_block += Widen(entry.first + "=" + entry.second);
      environment_block.push_back(L'\0');
    }
    environment_block.push_back(L'\0');
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  const DWORD flags = environment_block.empty() ? 0u : CREATE_UNICODE_ENVIRONMENT;
  const BOOL created = ::CreateProcessW(
      nullptr, mutable_command.data(), nullptr, nullptr, FALSE, flags,
      environment_block.empty() ? nullptr : environment_block.data(),
      nullptr, &startup, &info);
  if (created == 0) return false;
  out.process = info.hProcess;
  out.thread = info.hThread;
  out.id = info.dwProcessId;
  return true;
}

void WaitForExit(ChildProcess& child, unsigned long& exit_code) {
  exit_code = 0;
  if (child.process == nullptr) return;
  ::WaitForSingleObject(static_cast<HANDLE>(child.process), INFINITE);
  DWORD code = 0;
  ::GetExitCodeProcess(static_cast<HANDLE>(child.process), &code);
  exit_code = static_cast<unsigned long>(code);
}

void TerminateNow(ChildProcess& child, unsigned long exit_code) {
  if (child.process == nullptr) return;
  ::TerminateProcess(static_cast<HANDLE>(child.process), static_cast<UINT>(exit_code));
}

void CloseProcess(ChildProcess& child) {
  if (child.thread != nullptr) ::CloseHandle(static_cast<HANDLE>(child.thread));
  if (child.process != nullptr) ::CloseHandle(static_cast<HANDLE>(child.process));
  child.thread = nullptr;
  child.process = nullptr;
}

std::string ReadTextFile(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return std::string();
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

bool WriteTextFile(const std::string& path, const std::string& text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) return false;
  stream << text;
  stream.flush();
  return stream.good();
}

std::uint64_t ParseUintField(const std::string& text, const std::string& field) {
  const std::string needle = field + "=";
  const std::size_t at = text.find(needle);
  if (at == std::string::npos) return 0;
  std::uint64_t value = 0;
  std::size_t index = at + needle.size();
  bool any = false;
  while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
    value = value * 10u + static_cast<std::uint64_t>(text[index] - '0');
    ++index;
    any = true;
  }
  return any ? value : 0;
}

std::string WaitForFileText(const std::string& path) {
  for (;;) {
    const std::string text = ReadTextFile(path);
    if (!text.empty()) return text;
    ::Sleep(1);
  }
}

std::string WaitForGeneration(const std::string& path, std::uint64_t target) {
  for (;;) {
    const std::string text = ReadTextFile(path);
    if (!text.empty() && ParseUintField(text, "generation") >= target) return text;
    ::Sleep(1);
  }
}

}  // namespace isftest
