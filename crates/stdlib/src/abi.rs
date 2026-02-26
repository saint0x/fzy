use std::mem;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiSlice {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiMutSlice {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiPairI32 {
    pub left: i32,
    pub right: i32,
}

pub fn wrap_slice(bytes: &[u8]) -> AbiSlice {
    AbiSlice {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
    }
}

pub fn wrap_slice_mut(bytes: &mut [u8]) -> AbiMutSlice {
    AbiMutSlice {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
    }
}

pub fn assert_abi_safe_layouts() {
    assert_eq!(mem::size_of::<AbiSlice>(), mem::size_of::<usize>() * 2);
    assert_eq!(mem::size_of::<AbiMutSlice>(), mem::size_of::<usize>() * 2);
    assert_eq!(mem::size_of::<AbiPairI32>(), mem::size_of::<i32>() * 2);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrappers_are_canonical() {
        let mut bytes = vec![1_u8, 2, 3];
        let r = wrap_slice(&bytes);
        let w = wrap_slice_mut(&mut bytes);
        assert_eq!(r.len, 3);
        assert_eq!(w.len, 3);
        assert_abi_safe_layouts();
    }
}
