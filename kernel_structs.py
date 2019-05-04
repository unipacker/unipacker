from ctypes import *


class TEB(Structure):
    _fields_ = [
        ("seh_frame", c_uint32),  # fs:00h <-- important
        ("stack_base", c_uint32),  # fs:04h high addr
        ("stack_limit", c_uint32),  # fs:08h low addr
        ("sub_sys_tib", c_uint32),  # fs:0ch keep null
        ("fiber_data", c_uint32),  # fs:10h keep null
        ("arbitary_data", c_uint32),  # fs:14h keep null
        ("addr_of_teb", c_uint32),  # fs:18h <-- important
        ("envment_pointer", c_uint32),  # fs:1ch keep null
        ("process_id", c_uint32),  # fs:20h process id
        ("curr_thread_id", c_uint32),  # fs:24h current thread id
        ("act_rpc_handle", c_uint32),  # fs:28h keep null
        ("addr_of_tls", c_uint32),  # fs:2ch don't care
        ("proc_env_block", c_uint32)  # fs:30h <-- important
        # ... too much item
    ]


class PEB(Structure):
    _fields_ = [
        ("InheritedAddressSpace", c_ubyte),
        ("ReadImageFileExecOptions", c_ubyte),
        ("BeingDebugged", c_ubyte),
        ("BitField", c_ubyte),
        ("Mutant", c_uint32),
        ("ImageBaseAddress", c_uint32),
        ("Ldr", c_uint32),
        # ... too much item
    ]


class PEB_LDR_DATA(Structure):
    _fields_ = [
        ("Length", c_uint32),
        ("Initialized", c_uint32),
        ("SsHandle", c_uint32),
        ("InLoadOrderModuleList_First", c_uint32),
        ("InLoadOrderModuleList_Last", c_uint32),
        ("InMemoryOrderModuleList_First", c_uint32),
        ("InMemoryOrderModuleList_Last", c_uint32),
        ("InInitializationOrderModuleList_First", c_uint32),
        ("InInitializationOrderModuleList_Last", c_uint32),
        # ... too much item
    ]


class LIST_ENTRY(Structure):
    _fields_ = [
        ("Next", c_uint32),
        ("Prev", c_uint32),
        ("Value", c_uint32),
    ]

class _FILETIME(Structure):
    _pack_ = 1
    _fields_ = [
        ("dwLowDateTime", c_uint32),
        ("dwHighDateTime", c_uint32),
    ]
