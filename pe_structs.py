from ctypes import *


class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _fields_ = [
        ("Characteristics", c_uint32),  # fs:00h <-- important
        ("TimeDateStamp", c_uint32),  # fs:04h high addr
        ("ForwarderChain", c_uint32),  # fs:08h low addr
        ("Name", c_uint32),  # fs:0ch keep null
        ("FirstThunk", c_uint32),  # fs:10h keep null
    ]