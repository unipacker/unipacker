import pefile

from unicorn.x86_const import *


class ImageDump(object):

    def fix_section(self, section, next_section_vaddr):
        sec_name = section.Name.decode().strip("\x00")
        print(f"Size of raw data ({sec_name}): 0x{section.SizeOfRawData:02x}, "
              f"fixed: 0x{next_section_vaddr - section.VirtualAddress:02x}")
        section.SizeOfRawData = next_section_vaddr - section.VirtualAddress
        section.PointerToRawData = section.VirtualAddress

    def set_protections(self, section, protection):
        x, r, w = protection
        section.IMAGE_SCN_MEM_EXECUTE = x
        section.IMAGE_SCN_MEM_READ = r
        section.IMAGE_SCN_MEM_WRITE = w

    def fix_section_mem_protection(self, pe, ntp):
        for s in pe.sections:
            if s.Name in ntp:
                self.set_protections(s, ntp[s.Name])

    def fix_imports(self, pe):
        pass

    def dump_image(self, uc, base_addr, virtualmemorysize, apicall_handler, path="unpacked.exe"):
        ntp = apicall_handler.ntp
        loaded_img = uc.mem_read(base_addr, virtualmemorysize + 0x3000)
        pe = pefile.PE(data=loaded_img)

        pe.OPTIONAL_HEADER.AddressOfEntryPoint = uc.reg_read(UC_X86_REG_EIP)

        print("Fixing sections")
        for i in range(len(pe.sections) - 1):
            curr_section = pe.sections[i]
            next_section = pe.sections[i + 1]
            self.fix_section(curr_section, next_section.VirtualAddress)

        # handle last section differently: we have no next section's virtual address. Thus we take the end of the image
        self.fix_section(pe.sections[-1], virtualmemorysize)

        print("Fixing Memory Protection of Sections")
        self.fix_section_mem_protection(pe, ntp)

        print("Fixing Imports...")
        self.fix_imports(pe)

        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()

        print(f"Dumping state to {path}")
        pe.write(path)


class YZPackDump(ImageDump):

    def fix_imports(self, pe):  # TODO this is only for the YZPack sample for testing purposes
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = 0x60000
