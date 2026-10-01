# Persistence and recovery

## Files

```
<root>/
  LOCK                     exclusive single-writer lock, held for the session
  MANIFEST                 the committed state of the store (atomic replace target)
  tmp/MANIFEST.staged      staging file for the next manifest
  segments/seg-<20 digits>.isf   append-only records
```

## Two structures

**A record** is one durably committed operation. Its framing is:

| Field | Bytes |
| --- | --- |
| magic `ISFR` (little-endian u32) | 4 |
| format version | 2 |
| reserved | 2 |
| payload length | 4 |
| generation | 8 |
| operation kind | 4 |
| reserved | 4 |
| previous chain digest | 32 |
| payload digest | 32 |
| payload | variable |
| chain digest = SHA-256(header ‖ payload) | 32 |

Each record binds its predecessor's chain digest, so truncation, reordering,
and single-byte damage are all detectable. The chain continues across segment
boundaries: a new segment's first record references the previous segment's
head.

**A manifest** names the exact committed byte range of every segment and
commits to the state that the log produces:

* format version, manifest sequence;
* generation, control epoch, incarnation;
* the three identity allocators;
* session-open and last-close-clean flags;
* per segment: index, committed byte length, record count, chain head;
* a whole-state digest and the generation it describes;
* a SHA-256 checksum over everything above.

## The single commit point

```
1. append the record to the active segment
2. FlushFileBuffers the segment
3. write the manifest to tmp/MANIFEST.staged
4. FlushFileBuffers the staging file
5. read the staged bytes back through an independent handle and compare
6. ---- MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ----
```

Step 6 is the commit point. Everything before it may be lost without changing
authoritative state; everything after it is durable. A crash leaves at most an
unpublished record appended past the manifest's declared length, and recovery
truncates it. This is why an abrupt kill can only ever leave the store at the
last published generation or the one immediately after it.

## Recovery

1. Take the kernel-owned exclusive lock on `LOCK`.
2. Read the manifest under a hard size bound; verify magic, version, declared
   length, and checksum.
3. Refuse an absent, oversized, non-contiguous, or implausibly long segment
   table before allocating anything for it.
4. Delete segment files the manifest does not declare — the residue of a crash
   between creating a segment and publishing it.
5. Truncate every segment to its declared committed length, and report how many
   bytes were discarded.
6. Decode every record in order, verifying both digests, the cross-record
   chain, the cross-segment chain, and that generations are consecutive.
7. Apply the effects to rebuild authoritative state.
8. Verify the whole-state digest exactly at the generation the manifest names.
9. Verify that generation, epoch, incarnation, allocators, and session flags
   match what the manifest committed to.

Any failure in steps 2-9 refuses the store: ambiguous, corrupt, truncated,
incompatible, or partially published state is never silently accepted.

## Whole-state checkpoints

Recomputing a digest of the entire state on every commit costs time
proportional to the size of the store, so this is an explicit policy:

* `StateDigestPolicy::EveryCommit` — the manifest always carries a digest of
  the current generation. Maximum assurance.
* `StateDigestPolicy::OnCheckpoint` — the digest is refreshed by an explicit
  `Checkpoint()` call and on every clean close. Recovery verifies the last
  checkpoint it passes and always verifies the allocators and session flags,
  which are cheap and unconditional.

In both policies a clean close leaves a current digest, so the next reopen
verifies the whole materialized state.

## Single-writer exclusion

Mutation authority belongs to exactly one process. The store takes a Win32
exclusive lock (`LockFileEx`, fail-immediately) on `LOCK` and holds it for the
session. A second process is refused with `StoreLocked` before it can read or
interpret any state. The lock is owned by the kernel, so an abrupt process
death releases it with no cooperative act, and the successor gets a new
incarnation and an advanced control epoch.

## Format compatibility

The format identifier is `ISFSTORE`, version 1. A manifest or record carrying
an unknown version or an unknown operation kind is refused with
`StoreIncompatible`; it is never partially interpreted.
