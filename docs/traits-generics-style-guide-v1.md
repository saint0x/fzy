# Traits + Generics Style Guide v1

## Preferred Patterns

- Use concrete trait impl targets.
- Keep trait methods signature-only in trait declarations.
- Prefer generic call inference at call sites; use explicit specialization only when needed (`fn_name<Type>(...)`).
- Prefer type-qualified trait impl method calls in v1 (`Type.method(...)`).
- Use associated types/constants to keep trait APIs cohesive when they are part of the trait contract.

## Avoid

- Default trait method bodies.
- Generic trait methods.
- Ambiguous trait impl coverage for the same trait/type family.

## Example

```fzy
trait Show {
    fn render(v: i32) -> i32;
}

struct Item {
    value: i32,
}

impl Show for Item {
    fn render(v: i32) -> i32 {
        return v + 1
    }
}

fn id<T: Show>(v: T) -> T {
    return v
}

fn main() -> i32 {
    let item = Item { value: 5 }
    let out = id(item)
    return Item.render(out.value)
}
```
