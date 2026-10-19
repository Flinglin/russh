use std::fmt::Debug;
use std::ops::{Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeFull, RangeTo};

use crate::platform::{mlock, munlock};

/// A buffer which zeroes its memory on `.clear()`, `.resize()`, and
/// reallocations, to avoid copying secrets around.
pub struct CryptoVec {
    p: *mut u8, // `pub(crate)` allows access from platform modules
    size: usize,
    capacity: usize,
}

impl Debug for CryptoVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.size == 0 {
            return f.write_str("<empty>");
        }
        write!(f, "<{:?}>", self.size)
    }
}

impl Unpin for CryptoVec {}
unsafe impl Send for CryptoVec {}
unsafe impl Sync for CryptoVec {}

// Common traits implementations
impl AsRef<[u8]> for CryptoVec {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl AsMut<[u8]> for CryptoVec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.deref_mut()
    }
}

impl Deref for CryptoVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.p, self.size) }
    }
}

impl DerefMut for CryptoVec {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.p, self.size) }
    }
}

impl From<String> for CryptoVec {
    fn from(e: String) -> Self {
        CryptoVec::from(e.into_bytes())
    }
}

impl From<&str> for CryptoVec {
    fn from(e: &str) -> Self {
        CryptoVec::from(e.as_bytes())
    }
}

impl From<&[u8]> for CryptoVec {
    fn from(e: &[u8]) -> Self {
        CryptoVec::from_slice(e)
    }
}

impl From<Vec<u8>> for CryptoVec {
    fn from(e: Vec<u8>) -> Self {
        let mut c = CryptoVec::new_zeroed(e.len());
        c.clone_from_slice(&e[..]);
        c
    }
}

// Indexing implementations
impl Index<RangeFrom<usize>> for CryptoVec {
    type Output = [u8];
    fn index(&self, index: RangeFrom<usize>) -> &[u8] {
        self.deref().index(index)
    }
}
impl Index<RangeTo<usize>> for CryptoVec {
    type Output = [u8];
    fn index(&self, index: RangeTo<usize>) -> &[u8] {
        self.deref().index(index)
    }
}
impl Index<Range<usize>> for CryptoVec {
    type Output = [u8];
    fn index(&self, index: Range<usize>) -> &[u8] {
        self.deref().index(index)
    }
}
impl Index<RangeFull> for CryptoVec {
    type Output = [u8];
    fn index(&self, _: RangeFull) -> &[u8] {
        self.deref()
    }
}

impl IndexMut<RangeFull> for CryptoVec {
    fn index_mut(&mut self, _: RangeFull) -> &mut [u8] {
        self.deref_mut()
    }
}
impl IndexMut<RangeFrom<usize>> for CryptoVec {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut [u8] {
        self.deref_mut().index_mut(index)
    }
}
impl IndexMut<RangeTo<usize>> for CryptoVec {
    fn index_mut(&mut self, index: RangeTo<usize>) -> &mut [u8] {
        self.deref_mut().index_mut(index)
    }
}
impl IndexMut<Range<usize>> for CryptoVec {
    fn index_mut(&mut self, index: Range<usize>) -> &mut [u8] {
        self.deref_mut().index_mut(index)
    }
}

impl Index<usize> for CryptoVec {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        self.deref().index(index)
    }
}

// IO-related implementation
impl std::io::Write for CryptoVec {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.extend(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

// Default implementation
impl Default for CryptoVec {
    fn default() -> Self {
        CryptoVec {
            p: std::ptr::NonNull::dangling().as_ptr(),
            size: 0,
            capacity: 0,
        }
    }
}

const MAX_CAPACITY: usize = 1usize << (usize::BITS - 2);

#[cold]
#[inline(never)]
#[allow(clippy::panic)]
fn capacity_overflow(len: usize) -> ! {
    panic!("CryptoVec capacity overflow: {len}")
}

#[cold]
#[inline(never)]
#[allow(clippy::panic)]
fn length_overflow(lhs: usize, rhs: usize) -> ! {
    panic!("CryptoVec length overflow: {lhs} + {rhs}")
}

#[cold]
#[inline(never)]
fn alloc_failed(layout: std::alloc::Layout) -> ! {
    std::alloc::handle_alloc_error(layout)
}

#[inline]
fn checked_capacity(len: usize) -> usize {
    if len > MAX_CAPACITY {
        capacity_overflow(len);
    }
    len.next_power_of_two()
}

#[inline]
unsafe fn alloc_zeroed(capacity: usize) -> *mut u8 {
    debug_assert!(capacity > 0);
    let layout = unsafe { std::alloc::Layout::from_size_align_unchecked(capacity, 1) };
    let p = unsafe { std::alloc::alloc_zeroed(layout) };
    if p.is_null() {
        alloc_failed(layout);
    }
    let _ = mlock(p, capacity);
    p
}

#[inline]
fn checked_len_sum(lhs: usize, rhs: usize) -> usize {
    let sum = lhs.wrapping_add(rhs);
    if sum < lhs {
        length_overflow(lhs, rhs);
    }
    sum
}

impl CryptoVec {
    /// Creates a new `CryptoVec`.
    pub fn new() -> CryptoVec {
        CryptoVec::default()
    }

    /// Creates a new `CryptoVec` with `n` zeros.
    pub fn new_zeroed(size: usize) -> CryptoVec {
        if size == 0 {
            return CryptoVec::default();
        }

        let capacity = checked_capacity(size);
        let p = unsafe { alloc_zeroed(capacity) };
        CryptoVec { p, capacity, size }
    }

    /// Creates a new `CryptoVec` with capacity `capacity`.
    pub fn with_capacity(capacity: usize) -> CryptoVec {
        if capacity == 0 {
            return CryptoVec::default();
        }

        let capacity = checked_capacity(capacity);
        let p = unsafe { alloc_zeroed(capacity) };
        CryptoVec {
            p,
            capacity,
            size: 0,
        }
    }

    /// Length of this `CryptoVec`.
    ///
    /// ```
    /// assert_eq!(russh_cryptovec::CryptoVec::new().len(), 0)
    /// ```
    pub fn len(&self) -> usize {
        self.size
    }

    /// Returns `true` if and only if this CryptoVec is empty.
    ///
    /// ```
    /// assert!(russh_cryptovec::CryptoVec::new().is_empty())
    /// ```
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Resize this CryptoVec, appending zeros at the end. This may
    /// perform at most one reallocation, overwriting the previous
    /// version with zeros.
    pub fn resize(&mut self, size: usize) {
        if size <= self.capacity && size > self.size {
            // If this is an expansion within capacity, the memory is already zeroed.
            self.size = size
        } else if size <= self.size {
            // If this is a truncation, securely erase the extra memory.
            // Uses zeroize (optimization_barrier) to prevent dead-store elimination.
            unsafe {
                zeroize(self.p.add(size), self.size - size);
            }
            self.size = size;
        } else {
            // realloc ! and erase the previous memory.
            unsafe {
                let next_capacity = checked_capacity(size);
                let old_ptr = self.p;
                let next_ptr = alloc_zeroed(next_capacity);

                if self.capacity > 0 {
                    std::ptr::copy_nonoverlapping(old_ptr, next_ptr, self.size);
                    zeroize(old_ptr, self.size);
                    let _ = munlock(old_ptr, self.capacity);
                    let layout = std::alloc::Layout::from_size_align_unchecked(self.capacity, 1);
                    std::alloc::dealloc(old_ptr, layout);
                }

                self.p = next_ptr;
                self.capacity = next_capacity;
                self.size = size;
            }
        }
    }

    /// Clear this CryptoVec (retaining the memory).
    ///
    /// ```
    /// let mut v = russh_cryptovec::CryptoVec::new();
    /// v.extend(b"blabla");
    /// v.clear();
    /// assert!(v.is_empty())
    /// ```
    pub fn clear(&mut self) {
        self.resize(0);
    }

    /// Append a new byte at the end of this CryptoVec.
    pub fn push(&mut self, s: u8) {
        let size = self.size;
        self.resize(checked_len_sum(size, 1));
        unsafe { *self.p.add(size) = s }
    }

    /// Read `n_bytes` from `r`, and append them at the end of this
    /// `CryptoVec`. Returns the number of bytes read (and appended).
    pub fn read<R: std::io::Read>(
        &mut self,
        n_bytes: usize,
        mut r: R,
    ) -> Result<usize, std::io::Error> {
        let cur_size = self.size;
        let target_size = checked_len_sum(cur_size, n_bytes);
        self.resize(target_size);
        let s = unsafe { std::slice::from_raw_parts_mut(self.p.add(cur_size), n_bytes) };
        // Resize the buffer to its appropriate size.
        match r.read(s) {
            Ok(n) => {
                self.resize(cur_size + n);
                Ok(n)
            }
            Err(e) => {
                self.resize(cur_size);
                Err(e)
            }
        }
    }

    /// Write all this CryptoVec to the provided `Write`. Returns the
    /// number of bytes actually written.
    ///
    /// ```
    /// let mut v = russh_cryptovec::CryptoVec::new();
    /// v.extend(b"blabla");
    /// let mut s = std::io::stdout();
    /// v.write_all_from(0, &mut s).unwrap();
    /// ```
    pub fn write_all_from<W: std::io::Write>(
        &self,
        offset: usize,
        mut w: W,
    ) -> Result<usize, std::io::Error> {
        assert!(offset < self.size);
        // if we're past this point, self.p cannot be null.
        unsafe {
            let s = std::slice::from_raw_parts(self.p.add(offset), self.size - offset);
            w.write(s)
        }
    }

    /// Resize this CryptoVec, returning a mutable borrow to the extra bytes.
    ///
    /// ```
    /// let mut v = russh_cryptovec::CryptoVec::new();
    /// v.resize_mut(4).clone_from_slice(b"test");
    /// ```
    pub fn resize_mut(&mut self, n: usize) -> &mut [u8] {
        let size = self.size;
        self.resize(checked_len_sum(size, n));
        unsafe { std::slice::from_raw_parts_mut(self.p.add(size), n) }
    }

    /// Append a slice at the end of this CryptoVec.
    ///
    /// ```
    /// let mut v = russh_cryptovec::CryptoVec::new();
    /// v.extend(b"test");
    /// ```
    pub fn extend(&mut self, s: &[u8]) {
        let size = self.size;
        let added = s.len();
        self.resize(checked_len_sum(size, added));
        unsafe {
            std::ptr::copy_nonoverlapping(s.as_ptr(), self.p.add(size), s.len());
        }
    }

    /// Create a `CryptoVec` from a slice
    ///
    /// ```
    /// russh_cryptovec::CryptoVec::from_slice(b"test");
    /// ```
    pub fn from_slice(s: &[u8]) -> CryptoVec {
        let mut v = CryptoVec::new();
        v.resize(s.len());
        unsafe {
            std::ptr::copy_nonoverlapping(s.as_ptr(), v.p, s.len());
        }
        v
    }
}

impl Clone for CryptoVec {
    fn clone(&self) -> Self {
        let mut v = Self::new();
        v.extend(self);
        v
    }
}

// Drop implementation
impl Drop for CryptoVec {
    fn drop(&mut self) {
        if self.capacity > 0 {
            unsafe {
                zeroize(self.p, self.size);
                let _ = munlock(self.p, self.capacity);
                let layout = std::alloc::Layout::from_size_align_unchecked(self.capacity, 1);
                std::alloc::dealloc(self.p, layout);
            }
        }
    }
}

unsafe fn zeroize(dst: *mut u8, size: usize) {
    unsafe {
        std::ptr::write_bytes(dst, 0, size);
    }
    optimization_barrier(dst, size);
}

// https://github.com/RustCrypto/utils/blob/a9f3f461baa3e02f69a205c772b6b2d3eac4eda8/zeroize/src/barrier.rs
fn optimization_barrier(dst: *mut u8, size: usize) {
    #[cfg(all(
        not(miri),
        any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "arm64ec",
            target_arch = "loongarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "s390x",
            target_arch = "x86",
            target_arch = "x86_64",
        )
    ))]
    {
        let _ = size;
        unsafe {
            core::arch::asm!(
                "# {}",
                in(reg) dst,
                options(readonly, preserves_flags, nostack),
            );
        }
    }
    #[cfg(not(all(
        not(miri),
        any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "arm64ec",
            target_arch = "loongarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "s390x",
            target_arch = "x86",
            target_arch = "x86_64",
        )
    )))]
    {
        /// Custom version of `core::hint::black_box` implemented using
        /// `#[inline(never)]` and `read_volatile`.
        #[inline(never)]
        fn custom_black_box(p: *const u8) {
            let _ = unsafe { core::ptr::read_volatile(p) };
        }

        core::hint::black_box(dst);
        if size > 0 {
            custom_black_box(dst);
        }
    }
}
