//! Read-only memory mapping for large files, via raw libc calls so the crate
//! stays dependency-free. Falls back to ordinary reads for small files and
//! for platforms without mmap.

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::slice;

const MMAP_THRESHOLD: u64 = 1 << 20; // 1 MiB

pub struct Mmap {
    ptr: *mut u8,
    len: usize,
}

// The mapping is read-only and never mutated through this type.
unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Mmap {
    pub fn map(file: &File) -> io::Result<Option<Mmap>> {
        let len = file.metadata()?.len();
        if len == 0 || len < MMAP_THRESHOLD {
            return Ok(None);
        }
        let fd = file.as_raw_fd();
        let addr = unsafe {
            libc_mmap(
                ptr::null_mut(),
                len as usize,
                PROT_READ,
                MAP_PRIVATE,
                fd,
                0,
            )
        };
        if addr == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // Hint sequential access; failure is harmless.
        unsafe {
            libc_madvise(addr, len as usize, MADV_SEQUENTIAL);
        }
        Ok(Some(Mmap { ptr: addr as *mut u8, len: len as usize }))
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        unsafe {
            libc_munmap(self.ptr as *mut libc_void, self.len);
        }
    }
}

// Minimal local libc bindings (avoid pulling the libc crate).
#[allow(non_camel_case_types)]
type libc_void = std::ffi::c_void;
type OffT = i64;

const PROT_READ: i32 = 1;
const MAP_PRIVATE: i32 = 2;
const MAP_FAILED: *mut libc_void = !0usize as *mut libc_void;
#[cfg(any(target_os = "linux", target_os = "android"))]
const MADV_SEQUENTIAL: i32 = 4;
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
const MADV_SEQUENTIAL: i32 = 2;

extern "C" {
    fn mmap(
        addr: *mut libc_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: OffT,
    ) -> *mut libc_void;
    fn munmap(addr: *mut libc_void, len: usize) -> i32;
    fn madvise(addr: *mut libc_void, len: usize, advice: i32) -> i32;
}

unsafe fn libc_mmap(
    addr: *mut libc_void,
    len: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: OffT,
) -> *mut libc_void {
    mmap(addr, len, prot, flags, fd, offset)
}
unsafe fn libc_munmap(addr: *mut libc_void, len: usize) {
    munmap(addr, len);
}
unsafe fn libc_madvise(addr: *mut libc_void, len: usize, advice: i32) {
    madvise(addr, len, advice);
}

/// Owned or mapped bytes for a scanned file.
pub enum FileBytes {
    Heap(Vec<u8>),
    Mapped(Mmap),
}

impl FileBytes {
    pub fn load(file: &File) -> io::Result<FileBytes> {
        match Mmap::map(file)? {
            Some(m) => Ok(FileBytes::Mapped(m)),
            None => {
                let mut buf = Vec::new();
                use std::io::Read;
                let mut f = file;
                f.read_to_end(&mut buf)?;
                Ok(FileBytes::Heap(buf))
            }
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            FileBytes::Heap(v) => v,
            FileBytes::Mapped(m) => m.as_bytes(),
        }
    }
}
