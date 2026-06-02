# SPEC.md

# FzBounds

Deterministic Allocation, Capacity, and Runtime Budget Framework for FZY

Version: 0.1

Status: Design Specification

---

# Overview

FzBounds is a runtime and validation framework for FZY that enforces explicit resource limits and deterministic capacity planning.

The framework exists to make memory consumption, buffer growth, queue growth, connection counts, task counts, and runtime allocation behavior explicit and observable.

Unlike traditional memory-safe frameworks, FzBounds is concerned with:

- Capacity correctness
- Allocation predictability
- Runtime determinism
- Resource budgeting
- Production hardening
- Operational visibility

The framework is designed to sit underneath higher-level frameworks such as:

- fzweb
- fzjobs
- fzauth
- fzdata
- fzrealtime

and provide a common bounded execution model.

---

# Core Philosophy

Traditional systems allow:

txt Request arrives ↓ Allocate ↓ Allocate ↓ Allocate ↓ Allocate ↓ Hope memory exists 

FzBounds requires:

txt Declare budget ↓ Allocate during boot ↓ Freeze ↓ Execute within bounds ↓ Reject overflow 

The goal is:

> Production failures should be explicit, bounded, and observable.

Not:

> Production failures should become memory explosions.

---

# Design Goals

## Goal 1

Make resource consumption explicit.

Every resource should have a declared capacity.

Examples:

- bytes
- requests
- sockets
- tasks
- queues
- buffers
- maps
- lists
- channels
- streams

---

## Goal 2

Detect accidental growth.

The framework should expose:

fzy bounds.assert_no_heap_growth() 

to detect unexpected allocations.

---

## Goal 3

Support deterministic testing.

Tests should run against identical capacity constraints.

---

## Goal 4

Support production observability.

Operators should be able to inspect:

- remaining capacity
- peak capacity
- overflow events
- rejected operations

without additional instrumentation.

---

## Goal 5

Remain practical.

FzBounds does not prohibit allocation.

It controls allocation.

---

# Terminology

## Budget

A top-level resource declaration.

Example:

fzy let budget = bounds.budget {     max_memory_bytes: 64.mib,     max_tasks: 1000,     max_sockets: 512, } 

---

## Region

A bounded execution area.

Example:

fzy bounds.region("request") { } 

---

## Arena

A preallocated memory pool.

Example:

fzy let arena = bounds.arena(16.mib) 

---

## Freeze

Transition from initialization phase to runtime phase.

Example:

fzy bounds.freeze() 

After freeze:

- no implicit allocation
- capacity violations become runtime errors

---

## Capacity

Maximum permitted consumption.

Example:

txt headers = 64 connections = 1024 queue = 10000 

---

## Overflow

Attempted capacity violation.

Example:

txt capacity = 64 attempt = 65 

---

# Runtime Modes

## Strict Mode

No runtime allocation allowed.

Example:

fzy bounds.mode("strict") 

Behavior:

txt allocation after freeze ↓ error 

---

## Audit Mode

Allocations allowed.

Violations recorded.

Example:

fzy bounds.mode("audit") 

Behavior:

txt allocation ↓ audit event ↓ continue 

---

## Warn Mode

Violations logged.

Application continues.

Example:

fzy bounds.mode("warn") 

---

## Disabled Mode

Framework inactive.

Example:

fzy bounds.mode("off") 

---

# Budget Definition

Example:

fzy let budget = bounds.budget {     max_memory_bytes: 64.mib,      max_regions: 1000,      max_tasks: 10000,      max_sockets: 4096,      max_buffers: 5000,      max_channels: 1000,      max_queue_entries: 100000,      max_maps: 1000,      max_lists: 1000,      max_strings: 10000, } 

---

# Arena API

## Create

fzy let arena = bounds.arena(16.mib) 

---

## Allocate

fzy let ptr = arena.alloc(512) 

---

## Reset

fzy arena.reset() 

---

## Usage

fzy arena.used() arena.remaining() arena.capacity() 

---

# Bounded Containers

## Bounded List

fzy let users = bounds.list<User>(1024) 

Allowed:

fzy users.push(user) 

Overflow:

txt BoundsExceeded resource=list capacity=1024 attempt=1025 

---

## Bounded Map

fzy let cache = bounds.map<str, User>(5000) 

---

## Bounded Queue

fzy let queue = bounds.queue<Job>(10000) 

---

## Bounded Channel

fzy let channel = bounds.channel<Event>(2048) 

---

## Bounded Buffer

fzy let body = bounds.buffer(64.kib) 

---

# Regions

## Definition

fzy bounds.region("request") { } 

---

## Nested Regions

fzy bounds.region("request") {      bounds.region("json_decode") {      }  } 

---

## Tracking

Each region records:

- bytes allocated
- peak usage
- overflows
- execution time

---

# Freeze Model

## Boot Phase

Allowed:

txt allocate grow resize warm caches load configs 

---

## Runtime Phase

Forbidden:

txt grow list grow map grow queue allocate heap memory 

unless explicitly permitted.

---

# Validation APIs

## Assert No Heap Growth

fzy bounds.assert_no_heap_growth {     handler(req) } 

---

## Assert Capacity

fzy bounds.assert_capacity(queue) 

---

## Validate Region

fzy bounds.validate(region) 

---

# Telemetry

Metrics exposed automatically.

---

## Memory

txt bounds_memory_used bounds_memory_peak bounds_memory_remaining 

---

## Regions

txt bounds_region_count bounds_region_peak 

---

## Overflows

txt bounds_overflow_total 

---

## Allocations

txt bounds_allocations_total 

---

# Error Model

## BoundsExceeded

txt resource=list  capacity=1024  attempt=1025  region=request  timestamp=... 

---

## HeapGrowthViolation

txt allocation detected after freeze 

---

## RegionCapacityExceeded

txt region=request  budget=64k  actual=80k 

---

# fzweb Integration

Request lifecycle:

txt request arrives ↓ allocate request region ↓ bounded body buffer ↓ bounded header collection ↓ bounded route params ↓ execute ↓ destroy region 

Example:

fzy bounds.region("request") {      let headers = bounds.list<Header>(64)      let body = bounds.buffer(64.kib)  } 

---

# fzjobs Integration

Worker:

fzy let jobs = bounds.queue<Job>(100000)  let workers = bounds.pool(64) 

No unbounded queue growth.

---

# fzauth Integration

fzy let sessions = bounds.map<SessionId, Session>(100000) 

---

# fzrealtime Integration

fzy let room = bounds.list<Client>(5000) 

---

# Testing

Test mode can intentionally trigger failures.

Example:

fzy bounds.inject_overflow("request") 

Example:

fzy bounds.inject_allocation_failure() 

---

# Observability

Runtime inspection:

fzy bounds.inspect() 

Returns:

json {   "memory_used": 1048576,   "memory_peak": 2097152,   "regions": 500,   "overflows": 2 } 

---

# Future Features

## Compiler Integration

Compiler may statically verify:

txt list capacity queue capacity buffer capacity 

before runtime.

---

## Escape Analysis

Compiler may prove:

txt stack only 

execution paths.

---

## Allocation Heatmaps

Generate reports:

txt allocation by route allocation by task allocation by subsystem 

---

# Success Criteria

A FZY service should be able to run with:

txt bounded memory bounded queues bounded sockets bounded tasks bounded buffers bounded runtime allocation 

while remaining:

txt observable deterministic production-safe auditable 

The primary objective of FzBounds is to make resource consumption a declared property of software rather than an emergent property of software.