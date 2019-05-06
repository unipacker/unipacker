import os
import re
import struct
import sys
import threading
from cmd import Cmd
from random import choice
from time import sleep, time

import pefile
import r2pipe
import yara
from unicorn import *
from unicorn.x86_const import *

from apicalls import WinApiCalls
from headers import print_all_headers, print_dos_header, print_pe_header, print_opt_header, print_section_table, PE, \
    pe_write
from kernel_structs import TEB, PEB, PEB_LDR_DATA, LIST_ENTRY
from unpackers import get_unpacker
from utils import print_cols, merge, align, remove_range, get_string, convert_to_string

state = None


class State(object):

    def __init__(self, sync):
        self.imports = set()
        self.uc = None
        self.sample = None
        self.unpacker = None
        self.yara_matches = None
        self.virtualmemorysize = 0
        self.loaded_image = 0  # TODO rename to loaded_image
        self.BASE_ADDR = 0
        self.HOOK_ADDR = 0
        self.STACK_ADDR = 0
        self.STACK_SIZE = 0
        self.PEB_BASE = 0
        self.TEB_BASE = 0

        self.section_hopping_control = True
        self.write_execute_control = False
        self.allowed_addr_ranges = []

        self.breakpoints = set()
        self.mem_breakpoints = []
        self.data_lock = threading.Lock()
        self.instruction_lock = threading.Lock()  # TODO unused, do we need this?
        self.single_instruction = False
        self.apicall_handler = None
        self.startaddr = 0
        self.endaddr = 0

        self.log_mem_read = False
        self.log_mem_write = False
        self.log_instr = False
        self.log_apicalls = False

        self.sections_read = {}
        self.sections_written = {}
        self.write_targets = []
        self.sections_executed = {}
        self.api_calls = {}  # TODO rename to apicall_counter

        self.start = 0
        self.sync = sync


class Sync(object):

    def __init__(self):
        self.emulator_event = threading.Event()
        self.client_event = threading.Event()

    def switch(self, is_client):
        if is_client:
            self.client_event.clear()
            self.emulator_event.set()
            self.client_event.wait()
        else:
            self.emulator_event.clear()
            self.client_event.set()
            self.emulator_event.wait()


class Shell(Cmd):

    @staticmethod
    def continue_emu():
        state.sync.switch(False)

    def __init__(self):
        super().__init__()
        self.emu_started = False
        self.rules = None
        self.address = None

    def do_aaa(self, args):
        """Analyze absolutely all: Show a collection of stats about the current sample"""
        print("\x1b[31mFile analysis:\x1b[0m")
        print_cols([
            ("YARA:", ", ".join(map(str, state.yara_matches))),
            ("Chosen unpacker:", state.unpacker.__class__.__name__),
            ("Allowed sections:", ', '.join(state.unpacker.allowed_sections)),
            ("End of unpacking stub:", f"0x{state.endaddr:02x}" if state.endaddr != sys.maxsize else "unknown"),
            ("Section hopping detection:", "active" if state.section_hopping_control else "inactive"),
            ("Write+Exec detection:", "active" if state.write_execute_control else "inactive")
        ])
        print("\n\x1b[31mPE stats:\x1b[0m")
        print_cols([
            ("Declared virtual memory size:", f"0x{state.virtualmemorysize:02x}", "", ""),
            ("Actual loaded image size:", f"0x{len(state.loaded_image):02x}", "", ""),
            ("Image base address:", f"0x{state.BASE_ADDR:02x}", "", ""),
            ("Mapped stack space:", f"0x{state.STACK_ADDR:02x}", "-", f"0x{state.STACK_ADDR + state.STACK_SIZE:02x}"),
            ("Mapped hook space:", f"0x{state.HOOK_ADDR:02x}", "-", f"0x{state.HOOK_ADDR + 0x1000:02x}")
        ])
        self.do_i("i")
        print("\n\x1b[31mRegister status:\x1b[0m")
        self.do_i("r")

    def do_aaaa(self, args):
        """The version of aaa for people in a hurry: We know you don't want to waste your time staring at
boring static information. 'Auto-aaa' lets you get your hands dirty with emulation after
a quick glance at sample infos, without having to type 'r' yourself"""
        self.do_aaa(args)
        if any([state.log_instr, state.log_mem_read, state.log_mem_write]):
            sleep(2)
        self.do_r(args)

    def do_b(self, args):
        """Set breakpoints. All of the options below can be combined in one command any number of times

Code breakpoint:            b <address> [<addr2> ...]
    Classic breakpoint: Emulation will stop before executing the instruction at the given
    address.

API call breakpoint:        b $<api_call_name>
    Special case of code breakpoint: Stop the emulation when a certain API call is being made.
    If this function has been declared in the sample's import table, the breakpoint will be set
    instantly. If this function will be called in the future, but is somehow not known at the
    moment (dynamically resolved via GetProcAddress), we will still stop the execution on
    call. But until GetProcAddress is instructed to return the address of this function, the
    breakpoint will be marked as 'pending'. At this point we create a hook for the function
    and mark it as a normal breakpoint.

Memory breakpoint:          b m<address>[-<upper_limit>] ...
    When prefixing the address with an 'm', emulation will stop when this address is being
    read from or written to. Optionally you can set the breakpoint to watch over a whole
    range of memory, e.g. b m0x100-0x200.

Stack breakpoint:           b stack
    Special case of memory range breakpoint: watches the whole stack space

Show current breakpoints:   b"""
        code_targets = []
        mem_targets = []
        for arg in args.split(" "):
            if not arg:
                continue
            if arg == "stack":
                mem_targets += [(state.STACK_ADDR, state.STACK_ADDR + state.STACK_SIZE)]
            elif "m" == arg[0]:
                try:
                    parts = list(map(lambda p: int(p, 0), arg[1:].split("-")))
                    if len(parts) == 1:
                        lower = upper = parts[0]
                    else:
                        lower = min(parts)
                        upper = max(parts)
                    mem_targets += [(lower, upper)]
                except ValueError:
                    print(f"Error parsing address or range {arg}")
            elif "$" == arg[0]:
                arg = arg[1:]
                if arg in state.apicall_handler.hooks.values():
                    for addr, func_name in state.apicall_handler.hooks.items():
                        if arg == func_name:
                            code_targets += [addr]
                            break
                else:
                    state.apicall_handler.register_pending_breakpoint(arg)
            else:
                try:
                    code_targets += [int(arg, 0)]
                except ValueError:
                    print(f"Error parsing address {arg}")
        with state.data_lock:
            state.breakpoints.update(code_targets)
            state.mem_breakpoints = list(merge(state.mem_breakpoints + mem_targets))
            self.print_breakpoints()

    def print_breakpoints(self):
        current_breakpoints = list(map(try_parse_address, state.breakpoints))
        current_breakpoints += list(map(lambda b: f'{b} (pending)', state.apicall_handler.pending_breakpoints))
        print(f"Current breakpoints: {current_breakpoints}")
        current_mem_breakpoints = []
        for lower, upper in state.mem_breakpoints:
            if lower == state.STACK_ADDR and upper == state.STACK_ADDR + state.STACK_SIZE:
                current_mem_breakpoints += ["complete stack"]
            else:
                stack = lower >= state.STACK_ADDR and upper <= state.STACK_ADDR + state.STACK_SIZE
                text = f"0x{lower:02x}" + (f" - 0x{upper:02x}" if upper != lower else "")
                current_mem_breakpoints += [text + (" (stack)" if stack else "")]
        print(f"Current mem breakpoints: {current_mem_breakpoints}")

    def do_c(self, args):
        """Continue emulation. If it hasn't been started yet, it will act the same as 'r'"""
        with state.data_lock:
            state.single_instruction = False
        if self.emu_started:
            self.continue_emu()
        else:
            print("Emulation not started yet. Starting now...")
            self.do_r(args)

    # TODO do documentation
    def do_p(self, args):

        mapping = {
            "d": print_dos_header,
            "dos": print_dos_header,
            "p": print_pe_header,
            "pe": print_pe_header,
            "o": print_opt_header,
            "opt": print_opt_header,
            "a": print_all_headers,
            "all": print_all_headers,
            "s": print_section_table,
            "sections": print_section_table,
        }

        args_list = args.split(" ")

        for x in args_list:
            if x in mapping.keys():
                mapping[x](state.uc, state.BASE_ADDR)

    def do_dump(self, args):
        """Dump the emulated memory to file.

Usage:          dump [dest_path]

If no destination path is being specified, the dump will be carried out to
'unpacked.exe' in the current working directory. Dumped memory region:
From the image base address (usually 0x400000 or 0x10000000) to the end
of the loaded image: base address + virtual memory size + 0x3000 (buffer).
This memory region is being loaded into the first section of the PE file.
Like this, tools like Cutter are able to correctly parse the dump and display the
data at the right offsets.
Stack space and memory not belonging to the image address space is not dumped."""
        try:
            args = args or "unpacked.exe"
            state.unpacker.dump(state.uc, state.apicall_handler, path=args)
        except OSError as e:
            print(f"Error dumping to {args}: {e}")

    def do_onlydmp(self, args):
        args = args or "dump"
        pe_write(state.uc, state.BASE_ADDR, state.virtualmemorysize, args)

    def do_i(self, args):
        """Get status information

Show register values:       i r [reg names]
If no specific registers are provided, all registers are shown

Show imports:               i i
Static and dynamic imports are shown with their respective stub addresses in the loaded image"""
        info, *params = args.split(" ")
        mapping = {
            "r": print_regs,
            "registers": print_regs,
            "i": print_imports,
            "imports": print_imports
        }
        if info in mapping:
            mapping[info](params)
        else:
            print(f"Unrecognized info {info}")

    def do_x(self, args):
        """Dump memory at a specific address.

Usage:          x[/n] [{FORMAT}] LOCATION
Options:
    n       integer, how many items should be displayed

Format:     Either 'byte', 'int' (32bit) or 'str' (zero-terminated string)

Location:   address (decimal or hexadecimal form) or a $-prefixed register name (use the register's value as the
            destination address"""
        try:
            x_regex = re.compile(r"(?:/(\d*) )?(?:{(byte|int|str)} )?(.+)")
            result = x_regex.findall(args)
            if not result:
                print("Error parsing command")
                return
            n, t, addr = result[0]
            n = int(n, 0) if n else 1
            t = t or "int"

            if "$" in addr:
                alias = addr[1:]
                addr = get_reg_values()[alias]
            else:
                alias = ""
                addr = int(addr, 0)

            print_mem(state.uc, addr, n, t, alias)
        except Exception as e:
            print(f"Error parsing command: {e}")

    def do_set(self, args):
        """Set memory at a specific address to a custom value

Usage:      set [{FORMAT}] OPERATION LOCATION
Format:     either 'byte', 'int' (32bit) or 'str' (zero-terminated string)
Operation:  modifies the old value instead of overwriting it (anything else than '=' is disregarded in str mode!)
            either = (set), += (add to), *= (multiply with) or /= (divide by)
Location:   address (decimal or hexadecimal form) for memory writing, or a $-prefixed register name to write an integer
            to this specific register ('byte' and 'str' not supported for register mode!)"""
        regs = {
            "eax": UC_X86_REG_EAX,
            "ebx": UC_X86_REG_EBX,
            "ecx": UC_X86_REG_ECX,
            "edx": UC_X86_REG_EDX,
            "eip": UC_X86_REG_EIP,
            "esp": UC_X86_REG_ESP,
            "efl": UC_X86_REG_EFLAGS,
            "edi": UC_X86_REG_EDI,
            "esi": UC_X86_REG_ESI,
            "ebp": UC_X86_REG_EBP
        }
        set_regs_regex = re.compile(rf"\$({'|'.join(regs.keys())}) ([+\-*/]?=) (.+)")
        result = set_regs_regex.findall(args)
        if result:
            reg, op, value = result[0]
            try:
                value = int(value, 0)
                old_value = get_reg_values()[reg]
                if op == "+=":
                    value += old_value
                elif op == "-=":
                    value -= old_value
                elif op == "*=":
                    value *= old_value
                elif op == "/=":
                    value = old_value // value
                state.uc.reg_write(regs[reg], value)
            except Exception as e:
                print(f"Error: {e}")
            return

        set_regex = re.compile(r"(?:{(byte|int|str)} )?(.+) ([+\-*/]?=) (.+)")
        result = set_regex.findall(args)
        if not result:
            print("Error parsing command")
        else:
            try:
                t, addr, op, value = result[0]
                t = t or "int"
                addr = int(addr, 0)
                types = {
                    "byte": ("B", 1),
                    "int": ("<I", 4),
                    "str": ("", 0)
                }
                fmt, size = types[t]

                if fmt:
                    value = int(value, 0)
                    old_value, = struct.unpack(fmt, state.uc.mem_read(addr, size))
                    if op == "+=":
                        value += old_value
                    elif op == "-=":
                        value -= old_value
                    elif op == "*=":
                        value *= old_value
                    elif op == "/=":
                        value = old_value // value
                    to_write = struct.pack(fmt, value)
                else:
                    to_write = (value + "\x00").encode()
                state.uc.mem_write(addr, to_write)
            except Exception as e:
                print(f"Error: {e}")

    def do_r(self, args):
        """Start execution"""
        if self.emu_started:
            print("Emulation already started. Interpreting as 'c'")
            self.do_c(args)
            return
        self.emu_started = True
        threading.Thread(target=emu).start()
        state.sync.switch(True)

    def do_detect(self, args):
        """Stop emulation if certain states are detected.

Usage:              detect [OPTIONS]
Options:

    h, hop          Stop emulation when section hopping is detected: Many packers have one section filled with zeros which
                    is then filled with instructions at runtime. After unpacking, a jump is made into this section and the
                    unpacked code is being executed. This final jump triggers section hopping detection.
    wx, write_exec  Stop emulation when an instruction would be executed that has been modified before. Note that if the
                    unpacking stub is self-modifying, this detection will raise some false-positives instead of finding
                    the unpacked code."""
        state.section_hopping_control = any(x in args for x in ["h", "hop"])
        print(f"[{'x' if state.section_hopping_control else ' '}] section hopping detection")
        state.write_execute_control = any(x in args for x in ["wx", "write_exec"])
        print(f"[{'x' if state.write_execute_control else ' '}] Write+Exec detection")

    def do_rst(self, args):
        """Close the current sample and start at the initial file choosing prompt again."""
        if self.emu_started:
            state.uc.emu_stop()
            state.sync.switch(True)
        print("")
        init_sample(False)
        init_uc()
        self.emu_started = False
        state.sections_read = {}
        state.sections_written = {}
        state.write_targets = []
        state.sections_executed = {}
        state.api_calls = {}
        state.single_instruction = False
        self.update_prompt(state.startaddr)

    def do_s(self, args):
        """Execute a single instruction and return to the shell"""
        with state.data_lock:
            state.single_instruction = True
        if self.emu_started:
            self.continue_emu()
        else:
            print("Emulation not started yet. Starting now...")
            self.do_r(args)

    def do_del(self, args):
        """Removes breakpoints. Usage is the same as 'b', but the selected breakpoints and breakpoint ranges are being
deleted this time."""
        code_targets = []
        mem_targets = []
        if not args:
            state.breakpoints.clear()
            state.mem_breakpoints.clear()
            state.apicall_handler.pending_breakpoints.clear()
        for arg in args.split(" "):
            if not arg:
                continue
            if arg == "stack":
                mem_targets += [(state.STACK_ADDR, state.STACK_ADDR + state.STACK_SIZE)]
            elif "m" == arg[0]:
                try:
                    parts = list(map(lambda p: int(p, 0), arg[1:].split("-")))
                    if len(parts) == 1:
                        lower = upper = parts[0]
                    else:
                        lower = min(parts)
                        upper = max(parts)
                    mem_targets += [(lower, upper)]
                except ValueError:
                    print(f"Error parsing address or range {arg}")
            elif "$" == arg[0]:
                arg = arg[1:]
                if arg in state.apicall_handler.hooks.values():
                    for addr, func_name in state.apicall_handler.hooks.items():
                        if arg == func_name:
                            code_targets += [addr]
                            break
                elif arg in state.apicall_handler.pending_breakpoints:
                    state.apicall_handler.pending_breakpoints.remove(arg)
                else:
                    print(f"Unknown method {arg}, not imported or used in pending breakpoint")
            else:
                try:
                    code_targets += [int(arg, 0)]
                except ValueError:
                    print(f"Error parsing address {arg}")
        with state.data_lock:
            for t in code_targets:
                try:
                    state.breakpoints.remove(t)
                except KeyError:
                    pass
            new_mem_breakpoints = []
            for b_lower, b_upper in state.mem_breakpoints:
                for t_lower, t_upper in mem_targets:
                    new_mem_breakpoints += remove_range((b_lower, b_upper), (t_lower, t_upper))
            state.mem_breakpoints = list(merge(new_mem_breakpoints))
            self.print_breakpoints()

    def do_log(self, args):
        """Set logging level

Usage:          log [OPTIONS]
Options:

    i   Log every instruction that is executed
    r   Log memory READ access
    w   Log memory WRITE access
    s   Log system API calls

    a   Log everything"""
        if args == "a":
            args = "irsw"
        print("Log level:")
        state.log_mem_read = any(x in args for x in ["r", "read"])
        print(f"[{'x' if state.log_mem_read else ' '}] mem read")
        state.log_mem_write = any(x in args for x in ["w", "write"])
        print(f"[{'x' if state.log_mem_write else ' '}] mem write")
        state.log_instr = any(x in args for x in ["i", "instr"])
        print(f"[{'x' if state.log_instr else ' '}] instructions")
        state.log_apicalls = any(x in args for x in ["s", "sys"])
        print(f"[{'x' if state.log_apicalls else ' '}] API calls")

    def do_stats(self, args):
        """Print emulation statistics: In which section are the instructions located that were executed, which
sections have been read from and which have been written to"""
        print_stats()

    def do_yara(self, args):
        """Run YARA rules against the sample

Usage:          yara [<rules_path>]

If no rules file is specified, the default 'malwrsig.yar' is being used.
Those rules are then compiled and checked against the memory dump of the current emulator state (see 'dump' for further
details on this representation)"""
        if not args:
            if not self.rules:
                try:
                    self.rules = yara.compile(filepath="malwrsig.yar")
                    print("Default rules file used: malwrsig.yar")
                except:
                    print("\x1b[31mError: malwrsig.yar not found!\x1b[0m")
        else:
            self.rules = yara.compile(filepath=args)
        state.unpacker.dump(state.uc, state.apicall_handler)
        matches = self.rules.match("unpacked.exe")
        print(", ".join(map(str, matches)))

    def do_exit(self, args):
        """Exit un{i}packer"""
        if self.emu_started:
            state.uc.emu_stop()
            state.sync.switch(True)
        with open("fortunes") as f:
            fortunes = f.read().splitlines()
        print("\n\x1b[31m" + choice(fortunes) + "\x1b[0m")
        raise SystemExit

    def do_EOF(self, args):
        """Exit un{i}packer by pressing ^D"""
        self.do_exit(args)

    def update_prompt(self, addr):
        self.address = addr
        shell.prompt = f"\x1b[33m[0x{addr:02x}]> \x1b[0m"


def try_parse_address(addr):
    if addr in state.apicall_handler.hooks:
        return f"0x{addr:02x} ({state.apicall_handler.hooks[addr]})"
    return f"0x{addr:02x}"


def getVirtualMemorySize():
    r2 = r2pipe.open(state.sample)
    sections = r2.cmdj("iSj")
    min_offset = sys.maxsize
    total_size = 0
    for sec in sections:
        if sec['vaddr'] < min_offset:
            min_offset = sec['vaddr']
        if 'vsize' in sec:
            total_size += sec['vsize']
    r2.quit()
    total_size += (min_offset - state.BASE_ADDR)
    print(f"Virtualmemorysize: {hex(total_size)}")

    return total_size


def entrypoint(pe):
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase


def get_reg_values():
    return {
        "eax": state.uc.reg_read(UC_X86_REG_EAX),
        "ebx": state.uc.reg_read(UC_X86_REG_EBX),
        "ecx": state.uc.reg_read(UC_X86_REG_ECX),
        "edx": state.uc.reg_read(UC_X86_REG_EDX),
        "eip": state.uc.reg_read(UC_X86_REG_EIP),
        "esp": state.uc.reg_read(UC_X86_REG_ESP),
        "efl": state.uc.reg_read(UC_X86_REG_EFLAGS),
        "edi": state.uc.reg_read(UC_X86_REG_EDI),
        "esi": state.uc.reg_read(UC_X86_REG_ESI),
        "ebp": state.uc.reg_read(UC_X86_REG_EBP)
    }


def print_regs(args=None):
    reg_values = get_reg_values()

    if not args:
        regs = reg_values.keys()
    else:
        regs = map(lambda r: r.lower(), args)

    for reg in regs:
        print(f"{reg.upper()} = 0x{reg_values[reg]:02x}")


def print_mem(uc, base, num_elements, t="int", base_alias=""):
    if not base_alias:
        base_alias = f"0x{base:02x}"

    string = None
    if t == "str":
        string = get_string(base, uc)
        t = "byte"
        num_elements = len(string)

    types = {
        "byte": ("B", 1),
        "int": ("<I", 4)
    }
    fmt, size = types[t]
    for i in range(num_elements):
        item, = struct.unpack(fmt, uc.mem_read(base + i * size, size))
        print(f"{base_alias}+{i * 4} = 0x{item:02x}")

    if string is not None:
        print(f"String @0x{base:02x}: {string}")


def print_stack(uc, elements):
    esp = uc.reg_read(UC_X86_REG_ESP)
    print_mem(uc, esp, elements, base_alias="ESP")


def print_imports(args):
    lines_static = []
    lines_dynamic = []

    for addr, name in state.apicall_handler.hooks.items():
        try:
            module = state.apicall_handler.module_for_function[name]
        except KeyError:
            module = "?"
        if name in state.imports:
            lines_static += [(f"0x{addr:02x}", name, module)]
        else:
            lines_dynamic += [(f"0x{addr:02x}", name, module)]

    print("\n\x1b[31mStatic imports:\x1b[0m")
    print_cols(lines_static)
    print("\n\x1b[31mDynamic imports:\x1b[0m")
    print_cols(lines_dynamic)


def print_stats():
    duration = time() - state.start
    hours, rest = divmod(duration, 3600)
    minutes, seconds = divmod(rest, 60)
    print(f"\x1b[31mTime wasted emulating:\x1b[0m {int(hours):02} h {int(minutes):02} min {int(seconds):02} s")
    print("\x1b[31mAPI calls:\x1b[0m")
    print_cols([(name, amount) for name, amount in state.api_calls.items()])
    print("\n\x1b[31mInstructions executed in sections:\x1b[0m")
    print_cols([(name, amount) for name, amount in state.sections_executed.items()])
    print("\n\x1b[31mRead accesses:\x1b[0m")
    print_cols([(name, amount) for name, amount in state.sections_read.items()])
    print("\n\x1b[31mWrite accesses:\x1b[0m")
    print_cols([(name, amount) for name, amount in state.sections_written.items()])


def hook_code(uc, address, size, user_data):
    shell.update_prompt(address)
    if not state.sync.emulator_event.is_set():
        state.sync.client_event.set()  # previous command is finished, shell can start again
    state.sync.emulator_event.wait()

    with state.data_lock:
        breakpoint_hit = address in state.breakpoints
    if breakpoint_hit:
        print("\x1b[31mBreakpoint hit!\x1b[0m")
        pause_emu()
    if address == state.endaddr:
        print("\x1b[31mEnd address hit! Unpacking should be done\x1b[0m")
        state.unpacker.dump(uc, state.apicall_handler)
        pause_emu()

    if state.write_execute_control and address not in state.apicall_handler.hooks and (
            address < state.HOOK_ADDR or address > state.HOOK_ADDR + 0x1000):
        if any(lower <= address <= upper for (lower, upper) in sorted(state.write_targets)):
            print(f"\x1b[31mTrying to execute at 0x{address:02x}, which has been written to before!\x1b[0m")
            state.unpacker.dump(uc, state.apicall_handler)
            pause_emu()

    if state.section_hopping_control and address not in state.apicall_handler.hooks and address - 0x7 not in state.apicall_handler.hooks and (
            address < state.HOOK_ADDR or address > state.HOOK_ADDR + 0x1000):  # address-0x7 corresponding RET
        if not state.unpacker.is_allowed(address):
            sec_name = state.unpacker.get_section(address)
            print(f"\x1b[31mSection hopping detected into {sec_name}! Address: " + hex(address) + "\x1b[0m")
            state.unpacker.allow(address)
            state.unpacker.dump(uc, state.apicall_handler)
            pause_emu()

    curr_section = state.unpacker.get_section(address)
    if curr_section not in state.sections_executed:
        state.sections_executed[curr_section] = 1
    else:
        state.sections_executed[curr_section] += 1

    if address in state.apicall_handler.hooks:
        esp = uc.reg_read(UC_X86_REG_ESP)
        api_call_name = state.apicall_handler.hooks[address]
        ret, esp = state.apicall_handler.apicall(address, api_call_name, uc, esp, state.log_apicalls)

        if api_call_name not in state.api_calls:
            state.api_calls[api_call_name] = 1
        else:
            state.api_calls[api_call_name] += 1
        if ret is not None:  # might be a void function
            uc.mem_write(state.HOOK_ADDR, struct.pack("<I", ret))
        uc.reg_write(UC_X86_REG_ESP, esp)
    state.log_instr and print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    with state.data_lock:
        if state.single_instruction:
            state.sync.emulator_event.clear()


def pause_emu():
    state.sync.switch(False)


# Method is executed before memory access
def hook_mem_access(uc, access, address, size, value, user_data):
    curr_section = state.unpacker.get_section(address)
    access_type = ""
    if access == UC_MEM_READ:
        access_type = "READ"
        if curr_section not in state.sections_read:
            state.sections_read[curr_section] = 1
        else:
            state.sections_read[curr_section] += 1
        state.log_mem_read and print(">>> Memory is being READ at 0x%x, data size = %u" % (address, size))
    elif access == UC_MEM_WRITE:
        access_type = "WRITE"
        state.write_targets = list(merge(state.write_targets + [(address, address + size)]))
        if curr_section not in state.sections_written:
            state.sections_written[curr_section] = 1
        else:
            state.sections_written[curr_section] += 1
        state.log_mem_write and print(
            ">>> Memory is being WRITTEN at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
    else:
        for access_name, val in unicorn_const.__dict__.items():
            if val == access and "UC_MEM" in access_name:
                access_type = access_name[6:]  # remove UC_MEM from the access type
                print(f"Unexpected mem access type {access_type}, addr: 0x{address:02x}")
    if any(lower <= address <= upper for lower, upper in state.mem_breakpoints):
        print(f"\x1b[31mMemory breakpoint hit! Access {access_type} to 0x{address:02x}")
        pause_emu()


def hook_mem_invalid(uc, access, address, size, value, user_data):
    for access_name, val in unicorn_const.__dict__.items():
        if val == access and "UC_MEM" in access_name:
            print(f"Invalid memory access {access_name}, addr: 0x{address:02x}")
            state.uc.emu_stop()
            return


def emu():
    try:
        state.start = time()
        if state.endaddr == sys.maxsize:
            print(f"Emulation starting at {hex(state.startaddr)}")
        else:
            print(f"Emulation starting. Bounds: from {hex(state.startaddr)} to {hex(state.endaddr)}")
        # Start emulation from state.startaddr
        state.uc.emu_start(state.startaddr, sys.maxsize)

        # Result of the emulation
        print(">>> Emulation done. Below is the CPU context")
        print_regs()
        print()
        print_stats()
    except UcError as e:
        print(f"Error: {e}")
        state.unpacker.dump(state.uc, state.apicall_handler)
        state.sync.emulator_event.clear()
        shell.emu_started = False
        state.sync.client_event.set()
    finally:
        state.unpacker.dump(state.uc, state.apicall_handler)
        state.sync.emulator_event.clear()
        shell.emu_started = False
        state.sync.client_event.set()


def setup_processinfo():
    state.TEB_BASE = 0x200000
    state.PEB_BASE = state.TEB_BASE + 0x1000
    LDR_PTR = state.PEB_BASE + 0x1000
    LIST_ENTRY_BASE = LDR_PTR + 0x1000

    teb = TEB(
        -1,  # fs:00h
        state.STACK_ADDR + state.STACK_SIZE,  # fs:04h
        state.STACK_ADDR,  # fs:08h
        0,  # fs:0ch
        0,  # fs:10h
        0,  # fs:14h
        state.TEB_BASE,  # fs:18h (teb base)
        0,  # fs:1ch
        0xdeadbeef,  # fs:20h (process id)
        0xdeadbeef,  # fs:24h (current thread id)
        0,  # fs:28h
        0,  # fs:2ch
        state.PEB_BASE,  # fs:3ch (peb base)
    )

    peb = PEB(
        0,
        0,
        0,
        0,
        0xffffffff,
        state.BASE_ADDR,
        LDR_PTR,
    )

    ntdll_entry = LIST_ENTRY(
        LIST_ENTRY_BASE + 12,
        LIST_ENTRY_BASE + 24,
        0x77400000,
    )

    kernelbase_entry = LIST_ENTRY(
        LIST_ENTRY_BASE + 24,
        LIST_ENTRY_BASE + 0,
        0x73D00000,

    )

    kernel32_entry = LIST_ENTRY(
        LIST_ENTRY_BASE + 0,
        LIST_ENTRY_BASE + 12,
        0x755D0000,
    )

    ldr = PEB_LDR_DATA(
        0x30,
        0x1,
        0x0,
        LIST_ENTRY_BASE,
        LIST_ENTRY_BASE + 24,
        LIST_ENTRY_BASE,
        LIST_ENTRY_BASE + 24,
        LIST_ENTRY_BASE,
        LIST_ENTRY_BASE + 24,
    )

    teb_payload = bytes(teb)
    peb_payload = bytes(peb)

    ldr_payload = bytes(ldr)

    ntdll_payload = bytes(ntdll_entry)
    kernelbase_payload = bytes(kernelbase_entry)
    kernel32_payload = bytes(kernel32_entry)

    state.uc.mem_map(state.TEB_BASE, align(0x5000))
    state.uc.mem_write(state.TEB_BASE, teb_payload)
    state.uc.mem_write(state.PEB_BASE, peb_payload)
    state.uc.mem_write(LDR_PTR, ldr_payload)
    state.uc.mem_write(LIST_ENTRY_BASE, ntdll_payload)
    state.uc.mem_write(LIST_ENTRY_BASE + 12, kernelbase_payload)
    state.uc.mem_write(LIST_ENTRY_BASE + 24, kernel32_payload)
    state.uc.windows_tib = state.TEB_BASE


def load_dll(path_dll, start_addr):
    filename = os.path.splitext(os.path.basename(path_dll))[0]
    if not os.path.exists(f"DLLs/{filename}.ldll"):
        dll = pefile.PE(path_dll)
        loaded_dll = dll.get_memory_mapped_image(ImageBase=start_addr)
        with open(f"DLLs/{filename}.ldll", 'wb') as f:
            f.write(loaded_dll)
        state.uc.mem_map(start_addr, align(len(loaded_dll) + 0x1000))
        state.uc.mem_write(start_addr, loaded_dll)
    else:
        with open(f"DLLs/{filename}.ldll", 'rb') as dll:
            loaded_dll = dll.read()
            state.uc.mem_map(start_addr, align((len(loaded_dll) + 0x1000)))
            state.uc.mem_write(start_addr, loaded_dll)


def init_uc():
    # Calculate required memory
    pe = pefile.PE(state.sample)
    state.BASE_ADDR = pe.OPTIONAL_HEADER.ImageBase  # 0x400000
    state.unpacker.BASE_ADDR = state.BASE_ADDR
    state.virtualmemorysize = getVirtualMemorySize()
    state.STACK_ADDR = 0x0
    state.STACK_SIZE = 1024 * 1024
    STACK_START = state.STACK_ADDR + state.STACK_SIZE
    state.unpacker.secs += [{"name": "stack", "vaddr": state.STACK_ADDR, "vsize": state.STACK_SIZE}]
    state.HOOK_ADDR = STACK_START + 0x3000 + 0x1000

    # Start unicorn emulator with x86-32bit architecture
    state.uc = Uc(UC_ARCH_X86, UC_MODE_32)
    if state.startaddr is None:
        state.startaddr = entrypoint(pe)
    state.loaded_image = pe.get_memory_mapped_image(ImageBase=state.BASE_ADDR)
    state.virtualmemorysize = align(state.virtualmemorysize + 0x10000, page_size=4096)  # Space possible IAT rebuilding
    state.unpacker.virtualmemorysize = state.virtualmemorysize
    state.uc.mem_map(state.BASE_ADDR, state.virtualmemorysize)
    state.uc.mem_write(state.BASE_ADDR, state.loaded_image)

    setup_processinfo()

    # Load DLLs
    load_dll("DLLs/KernelBase.dll", 0x73D00000)
    load_dll("DLLs/kernel32.dll", 0x755D0000)
    load_dll("DLLs/ntdll.dll", 0x77400000)

    # initialize machine registers
    state.uc.mem_map(state.STACK_ADDR, state.STACK_SIZE)
    state.uc.reg_write(UC_X86_REG_ESP, state.STACK_ADDR + int(state.STACK_SIZE / 2))
    state.uc.reg_write(UC_X86_REG_EBP, state.STACK_ADDR + int(state.STACK_SIZE / 2))
    state.uc.mem_write(state.uc.reg_read(UC_X86_REG_ESP) + 0x8, bytes([1]))
    state.uc.reg_write(UC_X86_REG_ECX, state.startaddr)
    state.uc.reg_write(UC_X86_REG_EDX, state.startaddr)
    state.uc.reg_write(UC_X86_REG_ESI, state.startaddr)
    state.uc.reg_write(UC_X86_REG_EDI, state.startaddr)

    # setup section dict used for custom memory protection
    atn = {}  # Dict Address to Name: (StartVAddr, EndVAddr) -> Name
    ntp = {}  # Dict Name to Protection Tupel: Name -> (Execute, Read, Write)

    new_pe = PE(state.uc, state.BASE_ADDR)
    prot_val = lambda x, y: True if x & y != 0 else False
    for s in new_pe.section_list:
        atn[(
            s.VirtualAddress + state.BASE_ADDR,
            s.VirtualAddress + state.BASE_ADDR + s.VirtualSize)] = convert_to_string(
            s.Name)
        ntp[convert_to_string(s.Name)] = (
            prot_val(s.Characteristics, 0x20000000), prot_val(s.Characteristics, 0x40000000),
            prot_val(s.Characteristics, 0x80000000))

    # for s in pe.sections:
    #    atn[(s.VirtualAddress + state.BASE_ADDR, s.VirtualAddress + state.BASE_ADDR + s.Misc_VirtualSize)] = s.Name
    #    ntp[s.Name] = (s.IMAGE_SCN_MEM_EXECUTE, s.IMAGE_SCN_MEM_READ, s.IMAGE_SCN_MEM_WRITE)

    # init syscall handling and prepare hook memory for return values
    state.apicall_handler = WinApiCalls(state.BASE_ADDR, state.virtualmemorysize, state.HOOK_ADDR, state.breakpoints,
                                        state.sample, atn, ntp)
    state.uc.mem_map(state.HOOK_ADDR, 0x1000)
    state.unpacker.secs += [{"name": "hooks", "vaddr": state.HOOK_ADDR, "vsize": 0x1000}]
    hexstr = bytes.fromhex('000000008b0425') + struct.pack('<I', state.HOOK_ADDR) + bytes.fromhex(
        'c3')  # mov eax, [HOOK]; ret -> values of syscall are stored in eax
    state.uc.mem_write(state.HOOK_ADDR, hexstr)

    # handle imports
    for lib in pe.DIRECTORY_ENTRY_IMPORT:
        for func in lib.imports:
            func_name = func.name.decode() if func.name is not None else f"no name: 0x{func.address:02x}"
            dll_name = lib.dll.decode() if lib.dll is not None else "-- unknown --"
            state.imports.add(func_name)
            curr_hook_addr = state.apicall_handler.add_hook(state.uc, func_name, dll_name)
            state.uc.mem_write(func.address, struct.pack('<I', curr_hook_addr))

    hdr = PE(state.uc, state.BASE_ADDR)

    # TODO below new version but needs testing as it is crashing
    # import_table = get_imp(state.uc, hdr.data_directories[1].VirtualAddress, state.BASE_ADDR, hdr.data_directories[1].Size, True)
    # for lib in import_table:
    #    for func_name, func_addr in lib.imports:
    #        func_name = func_name if func_name is not None else f"no name: 0x{func_addr:02x}"
    #        dll_name = lib.Name if lib.Name is not None else "-- unknown --"
    #        imports.add(func_name)
    #        curr_hook_addr = state.apicall_handler.add_hook(state.uc, func_name, dll_name)
    #        state.uc.mem_write(func_addr, struct.pack('<I', curr_hook_addr))

    # Patch DLLs with hook
    # Hardcoded values used for speed improvement -> Offsets can be calculated with utils.calc_export_offset_of_dll
    state.apicall_handler.add_hook(state.uc, "VirtualProtect", "KernelBase.dll", 0x73D00000 + 0x1089f0)
    state.apicall_handler.add_hook(state.uc, "VirtualAlloc", "KernelBase.dll", 0x73D00000 + 0xd4600)
    state.apicall_handler.add_hook(state.uc, "VirtualFree", "KernelBase.dll", 0x73D00000 + 0xd4ae0)
    state.apicall_handler.add_hook(state.uc, "LoadLibraryA", "KernelBase.dll", 0x73D00000 + 0xf20d0)
    state.apicall_handler.add_hook(state.uc, "GetProcAddress", "KernelBase.dll", 0x73D00000 + 0x102870)

    state.apicall_handler.add_hook(state.uc, "VirtualProtect", "kernel32.dll", 0x755D0000 + 0x16760)
    state.apicall_handler.add_hook(state.uc, "VirtualAlloc", "kernel32.dll", 0x755D0000 + 0x166a0)
    state.apicall_handler.add_hook(state.uc, "VirtualFree", "kernel32.dll", 0x755D0000 + 0x16700)
    state.apicall_handler.add_hook(state.uc, "LoadLibraryA", "kernel32.dll", 0x755D0000 + 0x157b0)
    state.apicall_handler.add_hook(state.uc, "GetProcAddress", "kernel32.dll", 0x755D0000 + 0x14ee0)

    # Add hooks
    state.uc.hook_add(UC_HOOK_CODE, hook_code)
    state.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH, hook_mem_access)
    state.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)


def init_sample(show_fortune=True):
    try:
        histfile = ".unpacker_history"
        if not os.path.exists(histfile):
            open(histfile, "w+").close()
        with open(histfile) as f:
            known_samples = f.read().splitlines()[:10] + ["New sample..."]

        print("Your options for today:\n")
        lines = []
        for i, s in enumerate(known_samples):
            if s == "New sample...":
                lines += [(f"\t[{i}]", "\x1b[33mNew sample...\x1b[0m", "")]
            else:
                packer, name = s.split(";")
                lines += [(f"\t[{i}]", f"\x1b[34m{packer}:\x1b[0m", name)]
        print_cols(lines)
        print()

        success = False
        while not success:
            try:
                id = int(input("Enter the option ID: "))
            except ValueError:
                print("Error parsing ID")
                continue
            if 0 <= id < len(known_samples) - 1:
                state.sample = known_samples[id].split(";")[1]
                success = True
            elif id == len(known_samples) - 1:
                state.sample = input("Please enter the path to the file: ")
                if not os.path.isfile(state.sample):
                    print(f"Not a valid file!")
                else:
                    success = True
            else:
                print(f"Invalid ID. Allowed range: 0 - {len(known_samples) - 1}")

            try:
                state.unpacker, state.yara_matches = get_unpacker(state.sample)
            except RuntimeError as e:
                print(e)
                success = False
                continue
            state.startaddr = state.unpacker.get_entrypoint()
            state.endaddr, _ = state.unpacker.get_tail_jump()
            state.write_execute_control = state.unpacker.write_execute_control

        if show_fortune:
            with open("fortunes") as f:
                fortunes = f.read().splitlines()
            print(f"\n\x1b[31m{choice(fortunes)}\x1b[0m\n")
        else:
            print("")

        with open(histfile, "w") as f:
            f.writelines("\n".join(sorted(set([f"{state.yara_matches[-1]};{state.sample}"] + known_samples[:-1]))))
        state.allowed_addr_ranges = state.unpacker.get_allowed_addr_ranges()

        if not state.allowed_addr_ranges:
            state.section_hopping_control = False
    except EOFError:
        with open("fortunes") as f:
            fortunes = f.read().splitlines()
        print(f"\n\x1b[31m{choice(fortunes)}\x1b[0m\n")
        sys.exit(0)


if __name__ == '__main__':
    state = State(Sync())
    with open("banner") as f:
        print(f.read())
    init_sample()
    init_uc()

    shell = Shell()
    shell.update_prompt(state.startaddr)
    threading.Thread(target=shell.cmdloop).start()
