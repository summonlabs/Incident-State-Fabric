# Deadlock and lock-reentrancy audit

This audit was performed by reading every call path, not by relying on the test
suite to find problems.

## Locks in the system

| Lock | Kind | Held by |
| --- | --- | --- |
| `IncidentFabric::Impl::mutex` | `std::shared_mutex` | authoritative state and every commit |
| `IncidentFabric::Impl::observer_mutex` | `std::mutex` | the commit observer slot only |
| `LOCK` | Win32 `LockFileEx` | the process, for the whole session |

There are no other mutexes, no condition variables, no semaphores, and no
threads started by the library.

## Rules the code follows

1. **One acquisition per public call.** Every public method of
   `IncidentFabric` acquires `mutex` exactly once, by scope, and never calls
   another public method. There is no read-then-write reacquisition, no
   write-lock re-entry, and no helper that reacquires a held mutex. All internal
   helpers take a `LockedState`-style reference to data that is already
   protected; none of them locks.
2. **Lock ordering is a total order.** `observer_mutex` is the only second lock:
   `mutex` is never acquired while `observer_mutex` is held, so the two can
   never be inverted.
3. **No callbacks under a lock.** `Impl::Notify` copies the observer under
   `observer_mutex`, releases that mutex, and only then invokes the observer.
   `Commit` calls `Notify` after its `unique_lock` scope has ended. An observer
   is therefore free to re-enter the fabric, including committing again.
4. **No locking across process boundaries.** The `LOCK` file lock is process
   scoped and is never taken while `mutex` is held in a way that could block on
   another process's progress: it is taken once, during `Open`, before any
   state exists, and released during `Close`.
5. **No shutdown ordering hazard.** There are no workers to join. `Close`
   appends a session-close record, then closes the segment handle and releases
   the file lock. Nothing waits on work that the lock prevents from progressing.
6. **No cancellation paths.** The library performs no cancellable waits.

## References, views, and pointers

* `Store::Commit` takes a reference to the active `SegmentDescriptor` inside a
  local manifest copy and does not mutate that vector until after the reference
  is last used.
* `IncidentFabric::Open` takes a reference to the store's manifest for the
  replay checks and never uses it after the first commit, which republishes the
  manifest.
* Reads return by value. No view, pointer, or reference into authoritative
  state escapes a public call.
* `std::vector<EvidenceId>` membership lists are rebuilt by replay rather than
  cached across mutations.

## Defects found by this audit

* None outstanding. One earlier design used helper methods that took the state
  lock a second time; those were removed in favour of the single-acquisition
  rule above. A second earlier design invoked observers while holding the state
  lock; observers are now invoked after it is released, and
  `Concurrency.ObserversRunOutsideTheInternalLockAndMayReenter` proves the
  property by requiring another thread to complete a commit while an observer is
  blocked.
