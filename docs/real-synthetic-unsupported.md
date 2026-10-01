# Proof provenance: REAL, SYNTHETIC, UNSUPPORTED

Every claim in this repository is labelled with how it was established. This
file is the detailed version of the README summary.

## REAL

Behaviour genuinely exercised by the host operating system, filesystem,
process table, or package path.

| Claim | How it is exercised |
| --- | --- |
| Exclusive mutation authority | A second process is refused `StoreLocked` while a first holds the store, in `MultiProcess.MutationAuthorityIsExclusiveAndReleasedByDeath`. |
| Kernel-owned lock release on death | The holder is ended with `TerminateProcess`; the successor opens the same store without any cooperative step. |
| No accidental inheritance of authority | The successor observes `incarnation + 1` and an advanced control epoch, and a request minted for the dead incarnation is refused `StaleControlEpoch`. |
| Real durability | Every commit performs `FlushFileBuffers` on the segment and on a staged manifest, reads the staged bytes back through an independent handle, and publishes with `MoveFileExW(MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH)` on an NTFS volume. |
| Crash consistency at a single commit point | `MultiProcess.CrashAtEveryDurableBoundaryRecoversToOneWholeGeneration` terminates the worker with `TerminateProcess` at `before_append`, `after_write`, `after_flush`, `before_publish`, and `after_publish` for one named generation, and reopens from a fresh process. |
| Abrupt death mid-flight | `MultiProcess.AbruptKillMidCommitLeavesAWholeGenerationAndAPrefixOfHistory` kills a continuously committing worker as soon as it announces progress, then checks the recovered store against a completed reference run of the same workload. |
| Long paths | A store is created, written, closed, and reopened under a path longer than 260 characters. |
| Windows path semantics | Reserved device names, parent references, trailing dots and spaces, UNC and extended-length prefixes, and embedded NUL are refused before the filesystem is touched. |
| Invalid Unicode | A path containing an unpaired surrogate is refused with `InvalidArgument`. |
| Reparse points | A junction is created with `mklink /J` on a volume that supports it, and a store rooted on the junction is refused unless `allow_reparse_root` is set. |
| Package and downstream consumption | Install to a clean prefix, then an independent out-of-tree CMake project that calls `find_package(isf 1.0 CONFIG REQUIRED)`, compiles, links, and runs. |
| Sanitizer | A Debug build with the MSVC AddressSanitizer runtime runs the whole suite. |
| Static analysis | The MSVC analyzer (`/analyze`) runs over the first-party translation units. |

## SYNTHETIC

Modelled inputs. They are labelled as such wherever they appear, and none of
them is presented as a measurement of real equipment.

* Facility topology: racks, rows, halls, zones, power feeds, cooling loops,
  chillers, CRACs, PDUs, UPSs, generators, switches, servers, storage arrays,
  fire panels, suppression zones, access panels, sensors, and workloads are
  modelled as typed references, not as devices.
* Incident narratives: reports, severity assessments, containment proofs,
  recovery proofs, clearance attestations, and closure attestations are written
  by the test suite. No real incident data is present.
* Benchmark workloads: reported incidents over a modelled rack set, produced
  locally, with a single writer.
* Corrupted stores: byte flips, truncations, and rewritten manifests are
  produced by the test suite from valid stores.

## UNSUPPORTED

Not implemented, or implemented but not validated. Nothing here is claimed.

* No BMS, DCIM, PDU, UPS, generator, cooling, accelerator, RDMA, InfiniBand,
  NVLink, or vendor SDK integration, and no claim to own the internal
  execution, scheduling, routing, path authority, or device actuation of any
  adjacent system.
* No actuation of any kind: the fabric records decisions and never performs
  one.
* No recovery sequencing, workload migration, rack evacuation, or degraded-mode
  policy.
* No network protocol, no remote API, no multi-writer replication, no
  consensus, and no distributed coordination.
* No POSIX build. `src/detail/platform.cpp` targets Win32 and CMake refuses to
  configure on any other platform rather than shipping an unvalidated port.
* No network-filesystem validation. The commit point depends on rename and
  flush semantics that SMB and similar transports do not necessarily provide.
* No cryptographic authentication. Digests detect corruption, not forgery.
