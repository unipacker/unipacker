import os
import re
import struct
import sys
import threading
import yara
from cmd import Cmd
from random import choice
from time import sleep, time

import pefile
import r2pipe
from unicorn import *
from unicorn.x86_const import *

from apicalls import WinApiCalls
from unpackers import get_unpacker
from utils import print_cols, merge, align, remove_range

imports = set()
mu = None
counter = 0
virtualmemorysize = 0
BASE_ADDR = 0
HOOK_ADDR = 0
section_hopping_control = True
write_execute_control = False

breakpoints = set()
mem_breakpoints = []
data_lock = threading.Lock()
instruction_lock = threading.Lock()
emulator_event = threading.Event()
shell_event = threading.Event()
single_instruction = False

log_mem_read = False
log_mem_write = False
log_instr = False
log_syscalls = False

sections_read = {}
sections_written = {}
write_targets = []
sections_executed = {}
api_calls = {}

start = 0


class Shell(Cmd):

    @staticmethod
    def continue_emu():
        shell_event.clear()
        emulator_event.set()
        shell_event.wait()

    def __init__(self):
        super().__init__()
        self.emu_started = False
        self.rules = None

    def do_aaa(self, args):
        """Analyze absolutely all: Show a collection of stats about the current sample"""
        print("\x1b[31mFile analysis:\x1b[0m")
        print_cols([
            ("YARA:", ", ".join(map(str, yara_matches))),
            ("Chosen unpacker:", unpacker.__class__.__name__),
            ("Allowed sections:", ', '.join(unpacker.allowed_sections)),
            ("End of unpacking stub:", f"0x{endaddr:02x}" if endaddr != sys.maxsize else "unknown"),
            ("Section hopping detection:", "active" if section_hopping_control else "inactive"),
            ("Write+Exec detection:", "active" if write_execute_control else "inactive")
        ])
        print("\n\x1b[31mPE stats:\x1b[0m")
        print_cols([
            ("Declared virtual memory size:", f"0x{virtualmemorysize:02x}", "", ""),
            ("Actual loaded image size:", f"0x{len(loaded):02x}", "", ""),
            ("Image base address:", f"0x{BASE_ADDR:02x}", "", ""),
            ("Mapped stack space:", f"0x{STACK_ADDR:02x}", "-", f"0x{STACK_ADDR + STACK_SIZE:02x}"),
            ("Mapped hook space:", f"0x{HOOK_ADDR:02x}", "-", f"0x{HOOK_ADDR + 0x1000:02x}")
        ])
        self.do_i("i")
        print("\n\x1b[31mRegister status:\x1b[0m")
        self.do_i("r")

    def do_aaaa(self, args):
        """The version of aaa for people in a hurry: We know you don't want to waste your time staring at
boring static information. 'Auto-aaa' lets you get your hands dirty with emulation after
a quick glance at sample infos, without having to type 'r' yourself"""
        self.do_aaa(args)
        if any([log_instr, log_mem_read, log_mem_write]):
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
                mem_targets += [(STACK_ADDR, STACK_ADDR + STACK_SIZE)]
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
                if arg in apicall_handler.hooks.values():
                    for addr, func_name in apicall_handler.hooks.items():
                        if arg == func_name:
                            code_targets += [addr]
                            break
                else:
                    apicall_handler.register_pending_breakpoint(arg)
            else:
                try:
                    code_targets += [int(arg, 0)]
                except ValueError:
                    print(f"Error parsing address {arg}")
        with data_lock:
            breakpoints.update(code_targets)
            global mem_breakpoints
            mem_breakpoints = list(merge(mem_breakpoints + mem_targets))
            self.print_breakpoints()

    def print_breakpoints(self):
        current_breakpoints = list(map(try_parse_address, breakpoints))
        current_breakpoints += list(map(lambda b: f'{b} (pending)', apicall_handler.pending_breakpoints))
        print(f"Current breakpoints: {current_breakpoints}")
        current_mem_breakpoints = []
        for lower, upper in mem_breakpoints:
            if lower == STACK_ADDR and upper == STACK_ADDR + STACK_SIZE:
                current_mem_breakpoints += ["complete stack"]
            else:
                stack = lower >= STACK_ADDR and upper <= STACK_ADDR + STACK_SIZE
                text = f"0x{lower:02x}" + (f" - 0x{upper:02x}" if upper != lower else "")
                current_mem_breakpoints += [text + (" (stack)" if stack else "")]
        print(f"Current mem breakpoints: {current_mem_breakpoints}")

    def do_c(self, args):
        """Continue emulation. If it hasn't been started yet, it will act the same as 'r'"""
        with data_lock:
            global single_instruction
            single_instruction = False
        if self.emu_started:
            self.continue_emu()
        else:
            print("Emulation not started yet. Starting now...")
            self.do_r(args)

    def do_dump(self, args):
        """Dump the emulated memory to file.

Usage:          dump [dest_path]

If no destination path is being specified, the dump will be carried out to
'unpacked.dump' in the current working directory. Dumped memory region:
From the image base address (usually 0x400000 or 0x10000000) to the end
of the loaded image: base address + virtual memory size + 0x3000 (buffer).
Stack space and memory not belonging to the image address space is not dumped."""
        try:
            args = args or "unpacked.dump"
            dump_image(args)
        except OSError as e:
            print(f"Error dumping to {args}: {e}")

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

            print_mem(mu, addr, n, t, alias)
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
                mu.reg_write(regs[reg], value)
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
                    old_value, = struct.unpack(fmt, mu.mem_read(addr, size))
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
                mu.mem_write(addr, to_write)
            except Exception as e:
                print(f"Error: {e}")

    def do_r(self, args):
        """Start execution"""
        if self.emu_started:
            print("Emulation already started. Interpreting as 'c'")
            self.do_c(args)
            return
        self.emu_started = True
        shell_event.clear()
        emulator_event.set()
        threading.Thread(target=emu).start()
        shell_event.wait()

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
        global section_hopping_control, write_execute_control
        section_hopping_control = any(x in args for x in ["h", "hop"])
        print(f"[{'x' if section_hopping_control else ' '}] section hopping detection")
        write_execute_control = any(x in args for x in ["wx", "write_exec"])
        print(f"[{'x' if write_execute_control else ' '}] Write+Exec detection")

    def do_rst(self, args):
        """Close the current sample and start at the initial file choosing prompt again."""
        if self.emu_started:
            mu.emu_stop()
            shell_event.clear()
            emulator_event.set()
            shell_event.wait()
        print("")
        init_sample(False)
        init_uc()
        self.emu_started = False
        global single_instruction, sections_read, sections_written, sections_executed, write_targets, api_calls
        sections_read = {}
        sections_written = {}
        write_targets = []
        sections_executed = {}
        api_calls = {}
        single_instruction = False
        self.update_prompt(startaddr)

    def do_s(self, args):
        """Execute a single instruction and return to the shell"""
        with data_lock:
            global single_instruction
            single_instruction = True
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
        global mem_breakpoints
        if not args:
            breakpoints.clear()
            mem_breakpoints.clear()
            apicall_handler.pending_breakpoints.clear()
        for arg in args.split(" "):
            if not arg:
                continue
            if arg == "stack":
                mem_targets += [(STACK_ADDR, STACK_ADDR + STACK_SIZE)]
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
                if arg in apicall_handler.hooks.values():
                    for addr, func_name in apicall_handler.hooks.items():
                        if arg == func_name:
                            code_targets += [addr]
                            break
                elif arg in apicall_handler.pending_breakpoints:
                    apicall_handler.pending_breakpoints.remove(arg)
                else:
                    print(f"Unknown method {arg}, not imported or used in pending breakpoint")
            else:
                try:
                    code_targets += [int(arg, 0)]
                except ValueError:
                    print(f"Error parsing address {arg}")
        with data_lock:
            for t in code_targets:
                try:
                    breakpoints.remove(t)
                except KeyError:
                    pass
            new_mem_breakpoints = []
            for b_lower, b_upper in mem_breakpoints:
                for t_lower, t_upper in mem_targets:
                    new_mem_breakpoints += remove_range((b_lower, b_upper), (t_lower, t_upper))
            mem_breakpoints = list(merge(new_mem_breakpoints))
            self.print_breakpoints()

    def do_fix(self, args):
        """Fix the entry point in the sample's PE header

Usage:          fix [!]<addr>
The base address is subtracted from the provided address, in order to point to the correct physical entry point.
In order to stop this from happening, prepend the address with an exclamation mark"""
        if not args:
            print("Please provide the desired entry point address")
            return
        subtract_base = "!" != args[0]
        try:
            new_ep = int(args[1:], 0)
            if subtract_base:
                if new_ep < BASE_ADDR:
                    print(f"Error: 0x{new_ep:02x} is smaller than the base address (0x{BASE_ADDR:02x})")
                    return
                new_ep -= BASE_ADDR
            fix_ep(new_ep)
        except ValueError:
            print(f"Error parsing address {args}")

    def do_log(self, args):
        """Set logging level

Usage:          log [OPTIONS]
Options:

    i   Log every instruction that is executed
    r   Log memory READ access
    w   Log memory WRITE access
    s   Log system API calls

    a   Log everything"""
        global log_mem_read, log_mem_write, log_instr, log_syscalls
        if args == "a":
            args = "irsw"
        print("Log level:")
        log_mem_read = any(x in args for x in ["r", "read"])
        print(f"[{'x' if log_mem_read else ' '}] mem read")
        log_mem_write = any(x in args for x in ["w", "write"])
        print(f"[{'x' if log_mem_write else ' '}] mem write")
        log_instr = any(x in args for x in ["i", "instr"])
        print(f"[{'x' if log_instr else ' '}] instructions")
        log_syscalls = any(x in args for x in ["s", "sys"])
        print(f"[{'x' if log_syscalls else ' '}] API calls")

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
        dump_image("unpacked.dump")
        matches = self.rules.match("unpacked.dump")
        print(", ".join(map(str, matches)))

    def do_exit(self, args):
        """Exit un{i}packer"""
        if self.emu_started:
            mu.emu_stop()
            shell_event.clear()
            emulator_event.set()
            shell_event.wait()
        with open("fortunes") as f:
            fortunes = f.read().splitlines()
        print("\n\x1b[31m" + choice(fortunes) + "\x1b[0m")
        raise SystemExit

    def do_EOF(self, args):
        """Exit un{i}packer by pressing ^D"""
        self.do_exit(args)

    def update_prompt(self, addr):
        shell.prompt = f"\x1b[33m[0x{addr:02x}]> \x1b[0m"


def try_parse_address(addr):
    if addr in apicall_handler.hooks:
        return f"0x{addr:02x} ({apicall_handler.hooks[addr]})"
    return f"0x{addr:02x}"


def getVirtualMemorySize(sample):
    r2 = r2pipe.open(sample)
    sections = r2.cmdj("Sj")
    total_size = 0
    for sec in sections:
        if 'vsize' in sec:
            total_size += sec['vsize']
    r2.quit()

    return total_size


def entrypoint(pe):
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase


def get_reg_values():
    return {
        "eax": mu.reg_read(UC_X86_REG_EAX),
        "ebx": mu.reg_read(UC_X86_REG_EBX),
        "ecx": mu.reg_read(UC_X86_REG_ECX),
        "edx": mu.reg_read(UC_X86_REG_EDX),
        "eip": mu.reg_read(UC_X86_REG_EIP),
        "esp": mu.reg_read(UC_X86_REG_ESP),
        "efl": mu.reg_read(UC_X86_REG_EFLAGS),
        "edi": mu.reg_read(UC_X86_REG_EDI),
        "esi": mu.reg_read(UC_X86_REG_ESI),
        "ebp": mu.reg_read(UC_X86_REG_EBP)
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
    if t == "str":
        buf = ""
        i = 0
        while True:
            item, = struct.unpack("c", uc.mem_read(base + i, 1))
            if item == b"\x00":
                break
            buf += chr(item[0])
            i += 1
        print(f"String @0x{base:02x}: {buf}")
        t = "byte"
        num_elements = len(buf)

    types = {
        "byte": ("B", 1),
        "int": ("<I", 4)
    }
    fmt, size = types[t]
    for i in range(num_elements):
        item, = struct.unpack(fmt, uc.mem_read(base + i * size, size))
        print(f"{base_alias}+{i * 4} = 0x{item:02x}")


def print_stack(uc, elements):
    esp = uc.reg_read(UC_X86_REG_ESP)
    print_mem(uc, esp, elements, base_alias="ESP")


def print_imports(args):
    lines_static = []
    lines_dynamic = []

    for addr, name in apicall_handler.hooks.items():
        try:
            module = apicall_handler.module_for_function[name]
        except KeyError:
            module = "?"
        if name in imports:
            lines_static += [(f"0x{addr:02x}", name, module)]
        else:
            lines_dynamic += [(f"0x{addr:02x}", name, module)]

    print("\n\x1b[31mStatic imports:\x1b[0m")
    print_cols(lines_static)
    print("\n\x1b[31mDynamic imports:\x1b[0m")
    print_cols(lines_dynamic)


def print_stats():
    duration = time() - start
    hours, rest = divmod(duration, 3600)
    minutes, seconds = divmod(rest, 60)
    print(f"\x1b[31mTime wasted emulating:\x1b[0m {int(hours):02} h {int(minutes):02} min {int(seconds):02} s")
    print("\x1b[31mAPI calls:\x1b[0m")
    print_cols([(name, amount) for name, amount in api_calls.items()])
    print("\n\x1b[31mInstructions executed in sections:\x1b[0m")
    print_cols([(name, amount) for name, amount in sections_executed.items()])
    print("\n\x1b[31mRead accesses:\x1b[0m")
    print_cols([(name, amount) for name, amount in sections_read.items()])
    print("\n\x1b[31mWrite accesses:\x1b[0m")
    print_cols([(name, amount) for name, amount in sections_written.items()])


def hook_code(uc, address, size, user_data):
    global allowed_addr_ranges
    shell.update_prompt(address)
    if not emulator_event.is_set():
        shell_event.set()  # previous command is finished, shell can start again
    emulator_event.wait()

    with data_lock:
        breakpoint_hit = address in breakpoints
    if breakpoint_hit:
        print("\x1b[31mBreakpoint hit!\x1b[0m")
        pause_emu()
    if address == endaddr:
        print("\x1b[31mEnd address hit! Unpacking should be done\x1b[0m")
        pause_emu()

    if write_execute_control and address not in apicall_handler.hooks and (
            address < HOOK_ADDR or address > HOOK_ADDR + 0x1000):
        if any(lower <= address <= upper for (lower, upper) in sorted(write_targets)):
            print(f"\x1b[31mTrying to execute at 0x{address:02x}, which has been written to before!\x1b[0m")
            dump_image()
            pause_emu()

    if section_hopping_control and address not in apicall_handler.hooks and (
            address < HOOK_ADDR or address > HOOK_ADDR + 0x1000):
        allowed = False
        for start, end in allowed_addr_ranges:
            if start <= address <= end:
                allowed = True
                break
        if not allowed:
            sec_name = unpacker.get_section(address)
            print(f"\x1b[31mSection hopping detected into {sec_name}! Address: " + hex(address) + "\x1b[0m")
            curr_section_range = unpacker.get_section_range(sec_name)
            if curr_section_range:
                allowed_addr_ranges += [unpacker.get_section_range(sec_name)]
            fix_ep(address)
            dump_image()
            pause_emu()

    curr_section = unpacker.get_section(address)
    if curr_section not in sections_executed:
        sections_executed[curr_section] = 1
    else:
        sections_executed[curr_section] += 1

    if address in apicall_handler.hooks:
        esp = uc.reg_read(UC_X86_REG_ESP)
        api_call_name = apicall_handler.hooks[address]
        ret = 0
        if api_call_name in apicall_handler.apicall_mapping:
            ret, esp = apicall_handler.apicall(apicall_handler.hooks[address], uc, esp, log_syscalls)
        else:
            args = struct.unpack("<IIIIII", uc.mem_read(esp + 4, 24))
            print(f"Unimplemented API call at 0x{address:02x}: {api_call_name}, first 6 stack items: {list(map(hex, args))}")
        if api_call_name not in api_calls:
            api_calls[api_call_name] = 1
        else:
            api_calls[api_call_name] += 1
        uc.mem_write(HOOK_ADDR, struct.pack("<I", ret))
        uc.reg_write(UC_X86_REG_ESP, esp)
    log_instr and print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    with data_lock:
        if single_instruction:
            emulator_event.clear()


def pause_emu():
    emulator_event.clear()
    shell_event.set()
    emulator_event.wait()


def fix_ep(addr):
    pe_header_ptr, = struct.unpack("<I", mu.mem_read(BASE_ADDR + 0x3c, 4))
    file_header_pad = "x" * 20
    optional_pad = "x" * 16
    total_pad = "xx" + file_header_pad + optional_pad
    ep, = struct.unpack(f"{total_pad}I", mu.mem_read(BASE_ADDR + pe_header_ptr, 44))
    new_ep = addr - BASE_ADDR
    print(f"Original EP 0x{BASE_ADDR + ep:02x} is overwritten with 0x{BASE_ADDR + new_ep:02x}")
    mu.mem_write(BASE_ADDR + pe_header_ptr + len(total_pad) + 2, struct.pack("I", new_ep))


def dump_image(path="unpacked.dump"):
    print(f"Dumping state to {path}")
    with open(path, 'wb') as f:
        tmp = mu.mem_read(BASE_ADDR, virtualmemorysize + 0x3000)
        f.write(tmp)


# Method is executed before memory access
def hook_mem_access(uc, access, address, size, value, user_data):
    global write_targets
    curr_section = unpacker.get_section(address)
    access_type = ""
    if access == UC_MEM_READ:
        access_type = "READ"
        if curr_section not in sections_read:
            sections_read[curr_section] = 1
        else:
            sections_read[curr_section] += 1
        log_mem_read and print(">>> Memory is being READ at 0x%x, data size = %u" % (address, size))
    elif access == UC_MEM_WRITE:
        access_type = "WRITE"
        write_targets = list(merge(write_targets + [(address, address + size)]))
        if curr_section not in sections_written:
            sections_written[curr_section] = 1
        else:
            sections_written[curr_section] += 1
        log_mem_write and print(
            ">>> Memory is being WRITTEN at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
    else:
        for access_name, val in unicorn_const.__dict__.items():
            if val == access and "UC_MEM" in access_name:
                access_type = access_name[6:]  # remove UC_MEM from the access type
                print(f"Unexpected mem access type {access_type}, addr: 0x{address:02x}")
    if any(lower <= address <= upper for lower, upper in mem_breakpoints):
        print(f"\x1b[31mMemory breakpoint hit! Access {access_type} to 0x{address:02x}")
        pause_emu()


def hook_mem_invalid(uc, access, address, size, value, user_data):
    for access_name, val in unicorn_const.__dict__.items():
        if val == access and "UC_MEM" in access_name:
            print(f"Invalid memory access {access_name}, addr: 0x{address:02x}")
            mu.emu_stop()
            return


def emu():
    try:
        global start
        start = time()
        if endaddr == sys.maxsize:
            print(f"Emulation starting at {hex(startaddr)}")
        else:
            print(f"Emulation starting. Bounds: from {hex(startaddr)} to {hex(endaddr)}")
        # Start emulation from startaddr
        mu.emu_start(startaddr, sys.maxsize)

        # Result of the emulation
        print(">>> Emulation done. Below is the CPU context")
        print_regs()
        print()
        print_stats()

        dump_image()
        emulator_event.clear()
        shell.emu_started = False
        shell_event.set()
    except KeyboardInterrupt as k:
        mu.emu_stop()
        dump_image()
        emulator_event.clear()
        shell_event.set()
    except UcError as e:
        print(f"Error: {e}")
        dump_image()
        emulator_event.clear()
        shell.emu_started = False
        shell_event.set()


def init_uc():
    global virtualmemorysize, BASE_ADDR, STACK_ADDR, STACK_SIZE, HOOK_ADDR, mu, startaddr, loaded, apicall_handler
    # Calculate required memory
    virtualmemorysize = getVirtualMemorySize(sample)
    pe = pefile.PE(sample)
    BASE_ADDR = pe.OPTIONAL_HEADER.ImageBase  # 0x400000
    STACK_ADDR = 0x0
    STACK_SIZE = 1024 * 1024
    STACK_START = STACK_ADDR + STACK_SIZE
    unpacker.secs += [{"name": "stack", "vaddr": STACK_ADDR, "vsize": STACK_SIZE}]
    HOOK_ADDR = STACK_START + 0x3000 + 0x1000

    # Start unicorn emulator with x86-32bit architecture
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    if startaddr is None:
        startaddr = entrypoint(pe)
    loaded = pe.get_memory_mapped_image(ImageBase=BASE_ADDR)
    virtualmemorysize = len(loaded)
    mu.mem_map(BASE_ADDR, align(virtualmemorysize + 0x3000, page_size=4096))
    mu.mem_write(BASE_ADDR, loaded)

    # initialize machine registers
    mu.mem_map(STACK_ADDR, STACK_SIZE)
    mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + int(STACK_SIZE / 2))
    mu.reg_write(UC_X86_REG_EBP, STACK_ADDR + int(STACK_SIZE / 2))
    mu.mem_write(mu.reg_read(UC_X86_REG_ESP) + 0x8, bytes([1]))
    mu.reg_write(UC_X86_REG_ECX, startaddr)
    mu.reg_write(UC_X86_REG_EDX, startaddr)
    mu.reg_write(UC_X86_REG_ESI, startaddr)
    mu.reg_write(UC_X86_REG_EDI, startaddr)

    # init syscall handling and prepare hook memory for return values
    apicall_handler = WinApiCalls(BASE_ADDR, virtualmemorysize, HOOK_ADDR, breakpoints, sample)
    mu.mem_map(HOOK_ADDR, 0x1000)
    unpacker.secs += [{"name": "hooks", "vaddr": HOOK_ADDR, "vsize": 0x1000}]
    hexstr = bytes.fromhex('000000008b0425') + struct.pack('<I', HOOK_ADDR) + bytes.fromhex(
        'c3')  # mov eax, [HOOK]; ret -> values of syscall are stored in eax
    mu.mem_write(HOOK_ADDR, hexstr)

    # handle imports
    for lib in pe.DIRECTORY_ENTRY_IMPORT:
        for func in lib.imports:
            imports.add(func.name.decode())
            curr_hook_addr = apicall_handler.add_hook(mu, func.name.decode(), lib.dll.decode())
            mu.mem_write(func.address, struct.pack('<I', curr_hook_addr))

    # Add hooks
    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH, hook_mem_access)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)


def init_sample(show_fortune=True):
    global sample, unpacker, yara_matches, startaddr, endaddr, allowed_addr_ranges, section_hopping_control, write_execute_control
    global sections_executed, sections_read, sections_written
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
                sample = known_samples[id].split(";")[1]
                success = True
            elif id == len(known_samples) - 1:
                sample = input("Please enter the path to the file: ")
                if not os.path.isfile(sample):
                    print(f"Not a valid file!")
                else:
                    success = True
            else:
                print(f"Invalid ID. Allowed range: 0 - {len(known_samples) - 1}")

            try:
                unpacker, yara_matches = get_unpacker(sample)
            except RuntimeError as e:
                print(e)
                success = False
                continue
            startaddr = unpacker.get_entrypoint()
            endaddr, _ = unpacker.get_tail_jump()
            write_execute_control = unpacker.write_execute_control

        if show_fortune:
            with open("fortunes") as f:
                fortunes = f.read().splitlines()
            print(f"\n\x1b[31m{choice(fortunes)}\x1b[0m\n")
        else:
            print("")

        with open(histfile, "w") as f:
            f.writelines("\n".join(sorted(set([f"{yara_matches[-1]};{sample}"] + known_samples[:-1]))))
        allowed_addr_ranges = unpacker.get_allowed_addr_ranges()

        if not allowed_addr_ranges:
            section_hopping_control = False
    except EOFError:
        with open("fortunes") as f:
            fortunes = f.read().splitlines()
        print(f"\n\x1b[31m{choice(fortunes)}\x1b[0m\n")
        sys.exit(0)


if __name__ == '__main__':
    with open("banner") as f:
        print(f.read())
    init_sample()
    init_uc()

    shell = Shell()
    shell.update_prompt(startaddr)
    threading.Thread(target=shell.cmdloop).start()
