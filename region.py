"Module to interact with memory regions"

from ctypes import Structure, c_void_p, c_size_t, WinDLL, POINTER, byref, sizeof
from ctypes.wintypes import DWORD, HANDLE, LPCVOID, LPVOID, BOOL, LPDWORD

from pymem.memory import read_byte, read_bytes

__author__ = "SamsonPianoFingers"
__credits__ = ["SamsonPianoFingers"]
__license__ = "GPL"
__version__ = "0.03"
__maintainer__ = "SamsonPianoFingers"
__email__ = "itsthatguyagain3@gmail.com"
__status__ = "Prototype"

class Region(Structure):
    """Structure for memory region information
    Contains:
    BaseAddress - A pointer to the base address of the region of pages.
    AllocationBase
    Allocationprotect
    RegionSize
    State
    protect
    Type"""

    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("Allocationprotect", DWORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD)]

    def read(self, process_handle):
        """Reads the entire memory region and returns a bytearray
        Keyword arguments:
        process_handle -- handle to process
        """
        buffer = read_bytes(
            process_handle, self.BaseAddress, self.RegionSize)
        return buffer

    def dealloc(self, process_handle):
        """Frees this memory region from the process"""
        virtual_free(process_handle, self.BaseAddress)



__VirtualQuery__ = WinDLL('kernel32', use_last_error=True).VirtualQueryEx
__VirtualQuery__.argtypes = [HANDLE, LPCVOID, POINTER(Region), c_size_t]
__VirtualQuery__.restype = c_size_t

__VirtualAlloc__ = WinDLL('kernel32', use_last_error=True).VirtualAllocEx
__VirtualAlloc__.argtypes = [HANDLE, LPVOID, c_size_t, DWORD, DWORD]
__VirtualAlloc__.restype = LPVOID

__VirtualFree__ = WinDLL('kernel32', use_last_error=True).VirtualFreeEx
__VirtualFree__.argtypes = [HANDLE, LPVOID, c_size_t, DWORD]
__VirtualFree__.restype = BOOL

__CreateRemoteThread__ = WinDLL(
    'kernel32', use_last_error=True).CreateRemoteThreadEx
__CreateRemoteThread__.argtypes = [HANDLE, LPVOID, c_size_t, LPVOID, LPVOID,
                                   DWORD, LPVOID, LPDWORD]
__CreateRemoteThread__.restype = HANDLE

# change this depending on your system's minimumApplicationAddress
# cannot use WinDLL('kernel32').GetSystemInfo - causes crash on exit
__min_address__ = 0x10000


def virtual_query(process_handle, address):
    """Queries a process on a memory region - returns Region object

    Keyword arguments:
    process_handle -- handle to process
    address -- base address of the memory region
    """
    region = Region()
    __VirtualQuery__(process_handle, address, byref(region), sizeof(region))
    return region


def virtual_alloc(process_handle, address, size, allocation_type=0x00001000, protect=0x40):
    """Allocate memory in a remote process, default protection is PAGE_EXECUTE_READWRITE
    Default Allocation type is MEM_COMMIT
    An address of zero will allocate memory anywhere it is available
    Retuns allocated memory address in remote process

    Keyword arguments
    process_handle -- handle to process
    address -- address to allocate memory at
    size -- size in bytes of memory to allocate
    for allocation_type and protect see
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890(v=vs.85).aspx
    """
    return __VirtualAlloc__(process_handle, address, size, allocation_type, protect)


def virtual_free(process_handle, address, size=0, free_type=0x8000):
    """Free memory in a remote process, default type of deallcation is MEM_RELEASE
    Returns True on success, False on failure

    Keyword arguments
    process_handle -- handle to process
    address -- address to free memory
    size -- size in bytes of memory to free (use zero generally)
    free_type
    see https://msdn.microsoft.com/en-us/library/windows/desktop/aa366894(v=vs.85).aspx"""
    return __VirtualFree__(process_handle, address, size, free_type)


def create_remote_thread(process_handle, start_address,
                         parameter, creation_flags=0):
    """Creates a thread in the remote process at a specified address
    Returns a handle to the new thread on success, NULL on failure"""
    return __CreateRemoteThread__(process_handle, 0, 0, start_address, byref(DWORD(parameter)),
                                  creation_flags, 0, DWORD(0))


def map_all_regions(process_handle):
    """Returns a list of all memory regions in a process

    Keyword arguments:
    process_handle -  handle to process"""
    regions = []
    current_address = __min_address__
    while True:
        current_region = virtual_query(process_handle, current_address)
        if current_region.BaseAddress is None:
            break
        current_address = current_region.BaseAddress + current_region.RegionSize
        regions.append(current_region)
    return regions


def map_commit_regions(process_handle):
    "Returns a list of committed memory regions in a process"
    regions = []
    current_address = __min_address__
    while True:
        current_region = virtual_query(process_handle, current_address)
        if current_region.BaseAddress is None:
            break
        current_address = current_region.BaseAddress + current_region.RegionSize
        if current_region.State == 0x1000:
            regions.append(current_region)
    return regions


def dump_region(process_handle, region, file):
    "Dumps a single region into a file"
    buffer = read_bytes(
        process_handle, region.BaseAddress, region.RegionSize)
    with open(file, "rb") as current_file:
        current_file.write(buffer)


def dump_readable_memory(process_handle, file):
    "Dumps all readable memory in a process"
    regions = map_commit_regions(process_handle)
    with open(file, "wb") as current_file:
        for region in regions:
            buffer = read_bytes(
                process_handle, region.BaseAddress, region.RegionSize)
            current_file.write(buffer)


def find_bytes(process_handle, buffer):
    """Searches for a bytes-like object in process memory
    returns a list of addresses which matched at the time of scanning
    On a finding a match, skips the length of the match before searching for the next match

    Keyword arguments:
    process_handle -- handle to process
    buffer -- a bytes-like object; the bytes to scan for"""
    # gets a list of regions (filtered), scans each region for all matches
    # only get regions that are commited
    regions = map_commit_regions(process_handle)
    addresses = []
    for region in regions:
        if region.Type == 0x40000:  # don't process mapped memory e.g. files, emulation
            continue
        remote_buffer = read_bytes(
            process_handle, region.BaseAddress, region.RegionSize)
        q_offset = 0
        while True:
            offset = remote_buffer.find(buffer, q_offset)
            if offset == -1:
                break
            else:
                addresses.append(region.BaseAddress + offset)
                q_offset = offset + len(buffer)
    return addresses

def find_bytes_image(process_handle, buffer):
    """Searches for a bytes-like object in image process memory
    returns a list of addresses which matched at the time of scanning
    On a finding a match, skips the length of the match before searching for the next match

    Keyword arguments:
    process_handle -- handle to process
    buffer -- a bytes-like object; the bytes to scan for"""
    # gets a list of regions (filtered), scans each region for all matches
    # only get regions that are commited
    regions = map_commit_regions(process_handle)
    addresses = []
    for region in regions:
        if region.Type != 0x1000000:
            continue
        if region.Protect != 0x02:
            if region.Protect != 0x04:
                continue
        remote_buffer = read_bytes(
            process_handle, region.BaseAddress, region.RegionSize)
        q_offset = 0
        while True:
            offset = remote_buffer.find(buffer, q_offset)
            if offset == -1:
                break
            else:
                addresses.append(region.BaseAddress + offset)
                q_offset = offset + len(buffer)
    return addresses


def find_strings(process_handle, buffer):
    """Same as find bytes, but grabs the whole strings and returns them instead."""
    matches = find_bytes(process_handle, buffer)
    strings = []
    for str_p in matches:
        string = bytearray()
        byte = 1
        i = 0
        while byte != 0:
            byte = read_byte(process_handle, str_p + i)
            if byte != 0:
                string.append(byte)
            i = i + 1
        strings.append(str(string)[12:-2]) # bit of a hack but ya know, whatever
    return strings
