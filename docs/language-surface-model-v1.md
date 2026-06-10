# Language Surface Model v1

This is the canonical answer to "what is always available?" in production Fozzy.

## 1. Builtin Namespaces

These surfaces are always callable by namespace and are not ordinary imported modules:

- `env.*`
- `str.*`
- `json.*`
- `list.*`
- `map.*`
- `route.*`
- `proc.*`
- `term.*`

Examples:

```fzy
let home = env.get("HOME")
let payload = json.object(#{"ok": json.raw("true")})
let size = str.len(home)
```

Notes:

- `use core.env;` and `use core.str;` are marker imports for builtin namespaces, not sibling module imports.
- `proc.*` and `term.*` are always callable as runtime intrinsic namespaces. `use core.process;` and `use core.term;` import higher-level stdlib facades.

## 2. `use core.*` Facades

`use core.*` does one of two things:

1. Imports a higher-level stdlib facade.
2. Imports a facade and also satisfies a capability contract.

Canonical facades:

- `use core.text;`
- `use core.io;`
- `use core.path;`
- `use core.process;`
- `use core.term;`
- `use core.thread;`
- `use core.log;`
- `use core.http;`
- `use core.security;`

Non-facades:

- There is no `use core.c;` or `use core.ffi;` public stdlib import. C interop is modeled by language declarations plus tooling artifacts.

## 3. Capability-Gated Surface

These names participate in the module capability model:

- `time`
- `rng`
- `fs`
- `http`
- `proc`
- `mem`
- `thread`
- `log`
- `error`

Examples:

- `use core.http;` imports the HTTP facade and satisfies the `http` capability contract.
- `use core.log;` imports the logging facade and satisfies the `log` capability contract.
- `use core.thread;` imports the canonical task/thread facade and satisfies the `thread` capability contract.

## 4. Tooling

Use:

```bash
fz inspect surface --json
```

This emits the same classification in machine-readable form for editor integrations, docs tooling, and production onboarding.
