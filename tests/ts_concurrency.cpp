// Incident State Fabric - DCCP boundary 50
// Copyright 2026 Summon Software Labs.
// Licensed under the Apache License, Version 2.0.

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "isf/isf.h"
#include "test_framework.h"
#include "test_support.h"

using isftest::Fixture;
using isftest::RackScope;

namespace {

[[nodiscard]] isf::ReportIncidentRequest MakeReport(const Fixture& fixture,
                                                    isf::AuthorityId authority, std::uint64_t key,
                                                    const std::string& event) {
  isf::ReportIncidentRequest request;
  request.header.actor.authority = authority;
  request.header.actor.epoch = isftest::CurrentEpoch(fixture.fabric());
  request.header.key = isftest::Key(key);
  request.cls = isf::IncidentClass::Power;
  request.reported_severity = isf::Severity::Major;
  request.summary = "concurrent " + event;
  request.scope = RackScope("rack-conc");
  request.source_system = "synthetic";
  request.source_event_id = event;
  return request;
}

}  // namespace

ISF_TEST(Concurrency, ReadersObserveOnlyCommittedState) {
  Fixture fixture("conc-readers", isf::StateDigestPolicy::EveryCommit);
  constexpr int kWriters = 1;
  constexpr std::uint64_t kCommits = 120;
  constexpr int kReaders = 4;

  std::atomic<bool> stop{false};
  std::atomic<int> read_failures{0};
  std::atomic<int> write_failures{0};
  std::atomic<std::uint64_t> observed_generation{0};
  std::atomic<std::uint64_t> observed_audit{0};

  std::vector<std::thread> readers;
  readers.reserve(kReaders);
  for (int index = 0; index < kReaders; ++index) {
    readers.emplace_back([&] {
      while (!stop.load()) {
        const auto status = fixture.fabric().GetStatus();
        if (!status.ok()) {
          ++read_failures;
          continue;
        }
        // The generation, the record count, and the audit length are three
        // views of the same durable prefix and must always agree.
        if (status.value().record_count != status.value().generation.value() ||
            status.value().audit_count != status.value().generation.value()) {
          ++read_failures;
        }
        if (status.value().incident_count > status.value().generation.value()) {
          ++read_failures;
        }
        observed_generation.store(status.value().generation.value());
        observed_audit.store(status.value().audit_count);

        const auto listed = fixture.fabric().ListIncidents(isf::ListQuery{0, 1000});
        if (!listed.ok()) {
          ++read_failures;
          continue;
        }
        for (const isf::IncidentSummary& summary : listed.value()) {
          const auto view = fixture.fabric().GetIncident(summary.id);
          if (!view.ok()) ++read_failures;
        }
      }
    });
  }

  std::vector<std::thread> writers;
  for (int index = 0; index < kWriters; ++index) {
    writers.emplace_back([&, index] {
      for (std::uint64_t step = 0; step < kCommits; ++step) {
        const auto receipt = fixture.fabric().ReportIncident(MakeReport(
            fixture, fixture.operator_role, 100000 + static_cast<std::uint64_t>(index) * 10000 + step,
            "w" + std::to_string(index) + "-" + std::to_string(step)));
        if (!receipt.ok()) ++write_failures;
      }
    });
  }

  for (std::thread& writer : writers) writer.join();
  stop.store(true);
  for (std::thread& reader : readers) reader.join();

  ISF_CHECK_EQ(read_failures.load(), 0);
  ISF_CHECK_EQ(write_failures.load(), 0);
  const auto status = fixture.fabric().GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_CHECK_EQ(status.value().incident_count, kCommits);
  ISF_CHECK_EQ(status.value().record_count, status.value().generation.value());
  ISF_CHECK_EQ(status.value().audit_count, status.value().generation.value());
}

ISF_TEST(Concurrency, SimultaneousIdenticalRequestsCommitExactlyOnce) {
  Fixture fixture("conc-same-key", isf::StateDigestPolicy::EveryCommit);
  const isf::ReportIncidentRequest request =
      MakeReport(fixture, fixture.operator_role, 424242, "race");

  constexpr int kThreads = 8;
  std::atomic<int> committed{0};
  std::atomic<int> replayed{0};
  std::atomic<int> refused{0};
  std::vector<isf::IncidentId> incident_ids(kThreads);

  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int index = 0; index < kThreads; ++index) {
    threads.emplace_back([&, index] {
      const auto receipt = fixture.fabric().ReportIncident(request);
      if (!receipt.ok()) {
        ++refused;
        return;
      }
      incident_ids[static_cast<std::size_t>(index)] = receipt.value().incident;
      if (receipt.value().replayed) {
        ++replayed;
      } else {
        ++committed;
      }
    });
  }
  for (std::thread& thread : threads) thread.join();

  ISF_CHECK_EQ(committed.load(), 1);
  ISF_CHECK_EQ(replayed.load(), kThreads - 1);
  ISF_CHECK_EQ(refused.load(), 0);
  for (const isf::IncidentId id : incident_ids) {
    ISF_CHECK_EQ(id, incident_ids[0]);
  }
  const auto status = fixture.fabric().GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_CHECK_EQ(status.value().incident_count, std::uint64_t{1});
}

ISF_TEST(Concurrency, ObserversRunOutsideTheInternalLockAndMayReenter) {
  Fixture fixture("conc-observer", isf::StateDigestPolicy::EveryCommit);

  std::atomic<unsigned> observer_calls{0};
  std::atomic<bool> other_thread_started{false};
  std::atomic<bool> other_thread_done{false};
  std::atomic<bool> nested_commit_ok{false};
  std::atomic<bool> other_commit_ok{false};
  std::atomic<bool> observed_status_ok{false};
  std::mutex gate;
  std::condition_variable gate_condition;
  bool released = false;

  fixture.fabric().SetCommitObserver([&](const isf::CommitReceipt&) {
    const unsigned index = observer_calls.fetch_add(1);
    if (index != 0) return;
    // The first delivery blocks until another thread has completed a commit.
    // If the fabric held its internal lock while notifying, that other commit
    // could never finish and this test would hang: that is the proof.
    {
      std::unique_lock<std::mutex> lock(gate);
      gate_condition.wait(lock, [&] { return released; });
    }
    const auto status = fixture.fabric().GetStatus();
    observed_status_ok.store(status.ok());
    // A re-entrant commit from inside observer delivery must also work.
    const auto nested = fixture.fabric().ReportIncident(
        MakeReport(fixture, fixture.operator_role, 606060, "nested"));
    nested_commit_ok.store(nested.ok());
  });

  std::thread committer([&] {
    const auto receipt = fixture.fabric().ReportIncident(
        MakeReport(fixture, fixture.operator_role, 505050, "first"));
    observed_status_ok.store(observed_status_ok.load() && receipt.ok());
  });

  while (observer_calls.load() == 0) std::this_thread::yield();
  other_thread_started.store(true);

  std::thread other([&] {
    const auto receipt = fixture.fabric().ReportIncident(
        MakeReport(fixture, fixture.operator_role, 707070, "second"));
    other_commit_ok.store(receipt.ok());
    other_thread_done.store(true);
  });

  while (!other_thread_done.load()) std::this_thread::yield();
  {
    std::lock_guard<std::mutex> lock(gate);
    released = true;
  }
  gate_condition.notify_all();

  committer.join();
  other.join();

  ISF_CHECK(other_thread_started.load());
  ISF_CHECK(other_commit_ok.load());
  ISF_CHECK(nested_commit_ok.load());
  ISF_CHECK(observed_status_ok.load());
  ISF_CHECK_EQ(observer_calls.load(), 3u);

  const auto status = fixture.fabric().GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_CHECK_EQ(status.value().incident_count, std::uint64_t{3});
  ISF_CHECK_EQ(status.value().record_count, status.value().generation.value());
}

ISF_TEST(Concurrency, ReplacingTheObserverWhileCommittingIsSafe) {
  Fixture fixture("conc-observer-swap", isf::StateDigestPolicy::EveryCommit);
  std::atomic<int> calls{0};
  std::atomic<bool> stop{false};

  std::thread swapper([&] {
    while (!stop.load()) {
      fixture.fabric().SetCommitObserver([&](const isf::CommitReceipt&) { ++calls; });
      fixture.fabric().SetCommitObserver({});
    }
  });

  for (std::uint64_t index = 0; index < 200; ++index) {
    const auto receipt = fixture.fabric().ReportIncident(
        MakeReport(fixture, fixture.operator_role, 800000 + index, "swap" + std::to_string(index)));
    ISF_CHECK(receipt.ok());
  }
  stop.store(true);
  swapper.join();
  ISF_CHECK(calls.load() >= 0);
  const auto status = fixture.fabric().GetStatus();
  ISF_REQUIRE(status.ok());
  ISF_CHECK_EQ(status.value().incident_count, std::uint64_t{200});
}
