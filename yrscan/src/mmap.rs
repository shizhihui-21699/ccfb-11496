//! Read-only memory mapping for large files. Unix (mmap) and Windows
//! (CreateFileMapping) backends; no external crates.

use std::fs::File;
use std::io;

pub struct Mmap {
    ptr: *mut u8,
    len: usize,
}

// The mapping is read-only and shared; sending the slice across worker threads
// is sound because nothing mutates it.
unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Mmap {
    pub fn open(file: &File) -> io::Result<Mmap> {
        let meta = file.metadata()?;
        let len = meta.len() as usize;
        if len == 0 {
            return Ok(Mmap { ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(), len: 0 });
        }
        #[cfg(unix)]
        {
            let ptr = unsafe {
                libc_mmap(len, file)
            }?;
            Ok(Mmap { ptr, len })
        }
        #[cfg(not(unix))]
        {
            let ptr = unsafe { win_mmap(len, file) }?;
            Ok(Mmap { ptr, len })
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        if self.len == 0 {
            return;
        }
        #[cfg(unix)]
        unsafe {
            libc_munmap(self.ptr, self.len);
        }
        #[cfg(not(unix))]
        unsafe {
            win_munmap(self.ptr, self.len);
        }
    }
}

#[cfg(unix)]
mod unix_imp {
    use std::os::unix::io::AsRawFd;
    const PROT_READ: i32 = 1;
    const MAP_PRIVATE: i32 = 2;

    extern "C" {
        fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
        fn munmap(addr: *mut u8, len: usize) -> i32;
    }

    pub unsafe fn map(len: usize, file: &std::fs::File) -> std::io::Result<*mut u8> {
        let p = mmap(std::ptr::null_mut(), len, PROT_READ, MAP_PRIVATE, file.as_raw_fd(), 0);
        if p as isize == -1isize {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(p)
        }
    }

    pub unsafe fn unmap(ptr: *mut u8, len: usize) {
        munmap(ptr, len);
    }
}

#[cfg(unix)]
unsafe fn libc_mmap(len: usize, file: &File) -> std::io::Result<*mut u8> {
    unix_imp::map(len, file)
}
#[cfg(unix)]
unsafe fn libc_munmap(ptr: *mut u8, len: usize) {
    unix_imp::unmap(ptr, len)
}

#[cfg(not(unix))]
mod win_imp {
    use std::os::windows::io::AsRawHandle;
    type HANDLE = isize;
    type SIZE_T = usize;
    type DWORD = u32;
    type BOOL = i32;
    type LPVOID = *mut u8;

    extern "system" {
        fn CreateFileMappingW(
            h: HANDLE, attrs: *mut u8, protect: DWORD, hi: DWORD, lo: DWORD, name: *mut u16,
        ) -> HANDLE;
        fn MapViewOfFile(h: HANDLE, access: DWORD, off_hi: DWORD, off_lo: DWORD, n: SIZE_T)
            -> LPVOID;
        fn UnmapViewOfFile(base: LPVOID) -> BOOL;
        fn CloseHandle(h: HANDLE) -> BOOL;
    }

    const PAGE_READONLY: DWORD = 0x02;
    const FILE_MAP_READ: DWORD = 0x0004;

    pub unsafe fn map(len: usize, file: &std::fs::File) -> std::io::Result<*mut u8> {
        let hmap = CreateFileMappingW(
            file.as_raw_handle() as HANDLE,
            std::ptr::null_mut(),
            PAGE_READONLY,
            (len >> 32) as DWORD,
            len as DWORD,
            std::ptr::null_mut(),
        );
        if hmap == 0 || hmap == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let p = MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, len);
        CloseHandle(hmap);
        if p.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(p)
        }
    }

    pub unsafe fn unmap(ptr: *mut u8, _len: usize) {
        UnmapViewOfFile(ptr);
    }
}

#[cfg(not(unix))]
unsafe fn win_mmap(len: usize, file: &File) -> std::io::Result<*mut u8> {
    win_imp::map(len, file)
}
#[cfg(not(unix))]
unsafe fn win_munmap(ptr: *mut u8, len: usize) {
    win_imp::unmap(ptr, len)
}
