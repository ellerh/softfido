use crate::error::IOR;
use std::io::{Read, Write};
use std::mem::size_of;

// Some functions to read/write structs.  This should be safe for
// structs with C layout.

pub fn read_struct<T: Copy>(r: &mut dyn Read) -> IOR<T> {
    unsafe {
        let mut mem = std::mem::MaybeUninit::<T>::uninit();
        let ptr = mem.as_mut_ptr() as *mut u8;
        let bytes = std::slice::from_raw_parts_mut(ptr, size_of::<T>());
        r.read_exact(bytes)?;
        Ok(mem.assume_init())
    }
}

unsafe fn as_bytes<T: Copy>(p: &T) -> &[u8] {
    std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        size_of::<T>(),
    )
}

pub fn write_struct<T: Copy>(w: &mut dyn Write, s: &T) -> IOR<()> {
    w.write_all(unsafe { as_bytes(s) })
}

// Write the first len bytes of s to w.
pub fn write_struct_limited<T: Copy>(
    w: &mut dyn Write,
    s: &T,
    len: usize,
) -> IOR<()> {
    let bytes = unsafe { as_bytes(s) };
    w.write_all(&bytes[..len])
}

#[cfg(test)]
pub mod test {
    use std::mem::size_of;

    fn as_ptr<T>(bytes: &[u8]) -> *const T {
        assert_eq!(bytes.len(), size_of::<T>());
        let ptr = bytes.as_ptr().cast::<T>();
        assert!(ptr.align_offset(std::mem::align_of::<T>()) == 0);
        ptr
    }

    pub fn view_as<T: Copy>(bytes: &[u8]) -> &T {
        unsafe { as_ptr::<T>(bytes).as_ref().unwrap() }
    }
}
