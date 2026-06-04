use crate::abi::{AbiMutSlice, AbiSlice};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipKind {
    Owned,
    Borrowed,
    Out,
    InOut,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallbackBinding {
    pub slot: i32,
    pub context_id: u64,
}

pub fn bind_callback(slot: i32, context_id: u64) -> CallbackBinding {
    CallbackBinding { slot, context_id }
}

pub fn borrowed_view(bytes: &[u8]) -> AbiSlice {
    AbiSlice {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
    }
}

pub fn out_view(bytes: &mut [u8]) -> AbiMutSlice {
    AbiMutSlice {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
    }
}

pub fn ownership_label(kind: OwnershipKind) -> &'static str {
    match kind {
        OwnershipKind::Owned => "owned",
        OwnershipKind::Borrowed => "borrowed",
        OwnershipKind::Out => "out",
        OwnershipKind::InOut => "inout",
    }
}

#[cfg(test)]
mod tests {
    use super::{bind_callback, borrowed_view, out_view, ownership_label, OwnershipKind};

    #[test]
    fn c_views_and_ownership_labels_are_stable() {
        let mut payload = [1_u8, 2_u8, 3_u8];
        let borrowed = borrowed_view(&payload);
        let out = out_view(&mut payload);
        assert_eq!(borrowed.len, 3);
        assert_eq!(out.len, 3);
        assert_eq!(ownership_label(OwnershipKind::Owned), "owned");
        assert_eq!(ownership_label(OwnershipKind::Borrowed), "borrowed");
        assert_eq!(ownership_label(OwnershipKind::Out), "out");
        assert_eq!(ownership_label(OwnershipKind::InOut), "inout");
        let binding = bind_callback(7, 42);
        assert_eq!(binding.slot, 7);
        assert_eq!(binding.context_id, 42);
    }
}
