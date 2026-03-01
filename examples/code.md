# Examples Code Patterns (v1)

This file documents production-safe language patterns used in examples.

## Traits and Generics (Supported)

```fzy
trait Show {
    fn show(v: i32) -> i32;
}

struct Item {
    value: i32,
}

impl Show for Item {
    fn show(v: i32) -> i32 {
        return v
    }
}

fn id<T: Show>(v: T) -> T {
    return v
}

fn main() -> i32 {
    let it = Item { value: 5 }
    let out = id<Item>(it)
    return Item.show(out.value)
}
```

Rules:
- Generic calls must use explicit specialization (`id<Item>(...)`).
- Impl targets must be concrete types.
- Trait associated types/constants/default method bodies are not supported in v1.

## Macro/Attribute Status

Supported attribute surface:
- `#[repr(...)]`
- `#[ffi_panic(abort|error)]`

Unsupported attributes are rejected with diagnostics.

## References

- `docs/traits-generics-contract-v1.md`
- `docs/traits-generics-style-guide-v1.md`
- `docs/language-reference-v1.md`
