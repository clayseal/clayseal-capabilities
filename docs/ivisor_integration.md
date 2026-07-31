# Clay Seal x iVisor: the syscall-boundary integration

Design for putting Clay Seal's goal-derived envelope on top of iVisor
(`github.com/yuvvantalreja/iVisor`), a gVisor-style user-space application kernel
for Apple Silicon that intercepts every syscall of an untrusted Linux binary. Its
stated target workload is untrusted AI agent code (Python, LLM code executors,
bash). All file:line references are to the iVisor tree as inspected 2026-07-27.

## Why this is the substrate that makes the work SOTA

Today Clay Seal gates the tool calls an agent framework reports. That stream is
mediated by the agent, so a sufficiently capable or compromised agent can act
below it. iVisor gives the one action stream the agent cannot lie about or route
around: the syscall. If the envelope is enforced at the syscall boundary, the
agent cannot make a side effect the monitor does not see, because it cannot make
a syscall iVisor does not service.

The same stream is the asset the behavioral layer has been starved of. A
goal-conditional trajectory detector needs large volumes of realistic,
goal-labeled traces with ground truth. iVisor produces exactly that, at the speed
of running real workloads in isolation, with the syscall trace as ground truth.
So one substrate serves both the test problem (generate the corpus that lets us
design the detector) and the deployment problem (enforce its verdict). That
convergence is the reason to build here rather than continue only on AgentDojo
mock tool-calls.

## The single seam

Every intercepted syscall funnels through one function:

    // crates/ivisor-kernel/src/syscalls/mod.rs:216
    Dispatcher::dispatch(&mut self, task: &mut Task,
                         mem: &dyn GuestAddrSpace,
                         number: u64, args: [u64; 6]) -> u64

It is a flat function-pointer table; the body indexes `self.table[number]` and
calls the handler at `mod.rs:225`. At that point everything a decision needs is
already in scope:

- `number` and `args[6]`: the raw syscall and its arguments.
- `task`: `tid`, and `task.proc: Arc<Process>`.
- `Process` (`proc.rs:23`): `pid`, `ppid`, `cwd`, `mounts`, and the already
  attached policy handles `egress: Arc<EgressPolicy>` and
  `broker: Option<Arc<dyn FileBroker>>` (the Gofer).
- `mem`: read pointer arguments (paths, sockaddrs) out of guest memory.

Both roles attach here. Enforcement inserts an allow/deny before `mod.rs:225`.
Trajectory capture emits a typed event at the same point (the
`IVISOR_TRACE=syscalls` firehose already prints nr, name, args, and return at
`mod.rs:240`, but as unstructured stderr text). One seam, both jobs.

## How Clay Seal's layers map onto syscall primitives

The v0.1 layers are not thrown away. They become the policy that the seam
consults, expressed in syscall terms.

| Clay Seal layer | Syscall-level realization |
|---|---|
| Capability floor (goal-derived tool scope) | per-task allowed-syscall / resource set checked in `dispatch` |
| Destination binding (egress) | iVisor `EgressPolicy::allows` on connect (`net.rs:174`), fed a per-task destination set |
| Workspace containment | iVisor Gofer path containment (`gofer.rs:698`), already out-of-process |
| Partial-order conformance + danger gate | the behavioral detector, run over the typed syscall event stream |
| Statistical sensor | advisory, over the same stream |

Destination binding and workspace containment already exist inside iVisor as
`EgressPolicy` and the Gofer. Clay Seal does not reimplement them; it drives them
from the sealed goal. That is the integration: Clay Seal derives the envelope
before contamination and pushes it down as iVisor policy.

## Role B: inline enforcement hook (feasible on the perf budget)

iVisor's measured syscall floor is ~883 ns for the cheapest real syscall
(`getpid`), and ~1 microsecond typical (`BENCHMARKS.md:54-68`). That cost is the
hardware trap-and-return (svc to EL1 to hvc to VM-exit to dispatch to resume) and
is unavoidable by design. An inline policy check is an allowlist lookup plus a
small state-machine step, on the order of nanoseconds. It adds low single-digit
percent to the cheapest syscall and is noise on any syscall doing real work. A
synchronous allow/deny at the seam fits the budget. There is no need to make the
enforcement decision async or sampled. The shape is:

    if !policy.check(number, args, task) { return -EPERM }   // before mod.rs:225

## Role A: structured trajectory capture

The raw signal already flows through `dispatch`. The work is to replace the text
firehose at `mod.rs:240` with a typed emit (syscall nr, decoded name, args,
return, pid/tid, monotonic timestamp) into a per-run sink, producing one
trajectory record per workload run. This is net-new but low-risk, and it lands at
the same single choke point as Role B. The output is the goal-labeled,
ground-truth-traced corpus the behavioral detector trains and calibrates on, at a
realism AgentDojo cannot reach.

## The one hard prerequisite

iVisor's `EgressPolicy` is compiled from the `--allow` spec at launch and wrapped
in an immutable `Arc` shared by forked children (`runtime.rs:454-457`,
`proc.rs:139`). The only runtime-mutable state is the DNS-pinned IP set, driven
internally, not by an external API. The Gofer roots are likewise canonicalized
once at fork. So there is no way today to push a per-task destination set at
runtime, which is exactly what a goal-derived envelope must do.

This is the first thing to build: a runtime-mutable, atomically swappable policy
seam. The obvious target is the egress `rules: Vec<Rule>` at `net.rs:92`, moved
behind an `arc_swap` or `RwLock`, with a small API to install a per-task ruleset
at task creation. Everything else in Role B depends on this.

There is no pre-existing Clay Seal or external-policy scaffolding in the tree
(grep for clayseal/policy-hook returns nothing). This is a clean greenfield
integration onto a single dispatch path.

## Honest limits carried down

- Output manipulation with no syscall is still invisible. The syscall boundary
  governs effects, not what the agent says. This does not change at L1.
- In-goal wrong-target actions (a permitted syscall aimed at the wrong object)
  still need argument binding, now on decoded syscall args rather than tool args.
- The seam sees syscalls, not the agent's tool-level intent. Mapping a syscall
  trace back to the goal-derived plan (a `connect` to which host, a `write` to
  which path) is the translation layer Clay Seal owns above the seam.

## Phased plan

1. **Runtime-mutable policy seam.** Make `EgressPolicy` (and a task allowed-set)
   swappable at runtime; add an API to install a per-task envelope at task start.
   Prerequisite for everything below.
2. **Enforcement hook.** Consult the per-task policy in `dispatch` before handler
   invocation; deny with `-EPERM`. Measure the toll against `just bench-check` to
   confirm the budget holds.
3. **Typed trajectory events.** Emit a structured `SyscallEvent` per serviced
   syscall into a per-run record. This is the corpus generator.
4. **Envelope translation.** The Clay Seal side: derive the goal envelope, lower
   it to a per-task iVisor policy (destination set, path roots, syscall/resource
   scope), and lift the syscall event stream back to plan-level for the
   behavioral detector.
5. **Corpus + detector.** Run real agent workloads at scale under iVisor, capture
   traces, train and calibrate the goal-conditional detector on ground truth.

Steps 1 through 3 are changes in iVisor (coordinate with Yuvvan). Steps 4 and 5
are Clay Seal side. The seam in step 1 to 3 serves both enforcement and capture,
so it is the correct first build regardless of which role is prioritized.
