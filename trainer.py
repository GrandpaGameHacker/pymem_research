"""
Module for creating trainers for games or programs
can even be used to access multiple processes
NOTE:
the type_t argument in Address.__init__ and Pointer.__init__ is a string
e.g 'int' or 'float' or 'byte'
"""

from threading import Thread
from time import sleep

from pymem import memory

__author__ = "SamsonPianoFingers"
__credits__ = ["SamsonPianoFingers"]
__license__ = "GPL"
__version__ = "0.03"
__maintainer__ = "SamsonPianoFingers"
__email__ = "itsthatguyagain3@gmail.com"
__status__ = "Prototype"

__sizeof_type__ = {'int': 4, 'short': 2, 'byte': 1, 'float': 4, 'double': 8}

class Process:
    """Object that contains information on a process
    Keyword arguments:
    process -- pid (int) or process name (str)"""
    def __init__(self, process=0):
        self.attach_process(process)
    def attach_process(self, process):
        "Attach to a process"
        self.process = process
        if isinstance(process, int):
            self.process_handle = memory.open_process(process)
        elif isinstance(process, str):
            self.process_handle = memory.open_process_name(process)

    def close_process(self):
        """Close the current process"""
        memory.close_process(self.process.process_handle)

class Address:
    """Memory address class"""

    def __init__(self, address, type_t, process):
        """Address(address, type_t, process)

        Keyword arguments:
        address -- Location in the remote process's memory
        type_t -- a string representing variable type_t
        these are: 'byte', 'short', 'int, 'float, 'double'
        process -- a process object
        """
        self.address = address
        self.type_t = type_t
        self.size = __sizeof_type__.get(type_t)
        self.value = None
        self.lock_thread = None
        self.locked = False
        self.process = process

    def __exit__(self, exc_type_t, exc_value, traceback):
        self.unlock()

    def read(self):
        """Reads and formats the data at self.address in remote process
        Returns the data that was read.
        """
        if self.type_t == 'int':
            self.value = memory.read_integer(self.process.process_handle, self.address)
        elif self.type_t == 'short':
            self.value = memory.read_short(self.process.process_handle, self.address)
        elif self.type_t == 'byte':
            self.value = memory.read_byte(self.process.process_handle, self.address)
        elif self.type_t == 'float':
            self.value = memory.read_float(self.process.process_handle, self.address)
        elif self.type_t == 'double':
            self.value = memory.read_double(self.process.process_handle, self.address)
        return self.value

    def write(self, value):
        """Writes a value to self.address in remote process
        """
        if self.type_t == 'int':
            memory.write_integer(self.process.process_handle, self.address, value)
        elif self.type_t == 'short':
            memory.write_short(self.process.process_handle, self.address, value)
        elif self.type_t == 'byte':
            memory.write_byte(self.process.process_handle, self.address, value)
        elif self.type_t == 'float':
            memory.write_float(self.process.process_handle, self.address, value)
        elif self.type_t == 'double':
            memory.write_double(self.process.process_handle, self.address, value)

    def _lock_(self, value, interval=0.1):
        while self.locked is True:
            self.write(value)
            sleep(interval)

    def lock(self, value, interval=0.1):
        """Creates a thread which freezes self.address with specified value
        Keyword arguments:
        value -- value to freeze to
        (optional) interval -- freezing interval
        """
        if self.locked is not True:
            self.locked = True
            self.lock_thread = Thread(
                target=self._lock_, args=([value, interval]))
            self.lock_thread.daemon = True
            self.lock_thread.start()

    def unlock(self):
        """Unfreezes self.address by killing the lock thread"""
        self.locked = False


class Pointer(Address):
    """Memory pointer class"""

    def __init__(self, base_address, offset_list, type_t, process):
        """Pointer(base_address, offset_list, type_t, process)

        Keyword arguments:
        base_address -- base address of pointer in remote process
        offset_list -- a list of offsets to follow when resolving
        type_t -- a string representing variable type_t that the pointer points to
        these are: 'byte', 'short', 'int, 'float, 'double'
        process -- a process object
        """
        super(Pointer, self).__init__(0, type_t, process)
        self.base_address = base_address
        self.offset_list = offset_list
        self.resolve()

    def resolve(self):
        """Resolves the pointer and caches it for read/write"""
        self.address = memory.resolve_multi_pointer(
            self.process.process_handle, self.base_address, self.offset_list)

    def resolve_and_read(self):
        """Resolves and reads the pointer. Also caches the pointer
        Returns the data that was read"""
        self.resolve()
        return self.read()

    def resolve_and_write(self, value):
        """Resolves and writes to pointer. Also caches the pointer

        Keyword arguments:
        value -- value to write to address pointed at by pointer"""
        self.resolve()
        self.write(value)


class Patch:
    """Memory patching class"""

    def __init__(self, address, patch_bytes, process):
        """Patch(address, patch_bytes, process)

        Keyword arguments:
        address -- address to patch
        patch_bytes -- bytes to change at self.address"""
        self.address = address
        self.patch_bytes = patch_bytes
        self.length = len(patch_bytes)
        self.process = process
        self.original_bytes = memory.read_bytes(
            self.process.process_handle, self.address, self.length
        )

    def patch(self):
        """Applies patch to memory"""
        memory.write_bytes(self.process.process_handle, self.address, self.patch_bytes)

    def restore(self):
        """Restores original bytes, removing the patch"""
        memory.write_bytes(self.process.process_handle, self.address, self.original_bytes)


class PatchGroup:
    """Keeps a list of related patches, and patches them all at the same time
    Keyword arguments:
    patch_list -- a list of Patch objects
    """
    def __init__(self, patch_list):
        self.patch_list = patch_list

    def append(self, patch):
        """Appends a Patch object to the patch list"""
        if isinstance(patch, Patch):
            self.patch_list.append(patch)

    def extend(self, patch_list):
        """Appends a list of Patch objects to the patch list"""
        for patch in patch_list:
            if not isinstance(patch, Patch):
                return
            self.patch_list.extend(patch_list)

    def patch(self):
        """Applies all patches to memory"""
        for patch in self.patch_list:
            if isinstance(patch, Patch):
                patch.patch()

    def restore(self):
        """Restores all original bytes, removing every patch in the list"""
        for patch in self.patch_list:
            if isinstance(patch, Patch):
                patch.restore()
