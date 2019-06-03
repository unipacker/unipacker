import argparse
import builtins
import os
import re
import struct
import sys
import threading
from random import choice
from time import time, sleep

import yara
from cmd2 import Cmd
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, \
    UC_X86_REG_EIP, UC_X86_REG_EFLAGS, UC_X86_REG_EDI, UC_X86_REG_ESI, UC_X86_REG_EBP

import unipacker
from unipacker.core import UnpackerClient, UnpackerEngine, Sample
from unipacker.headers import print_dos_header, print_pe_header, print_opt_header, print_all_headers, \
    print_section_table, \
    pe_write
from unipacker.io_handler import IOHandler
from unipacker.utils import get_reg_values, get_string, print_cols, merge, remove_range

_print = builtins.print


def file_or_dir(path):
    if os.path.exists(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} is not a valid path")


class Shell(Cmd, UnpackerClient):

    def __init__(self):
        try:
            Cmd.__init__(self)
            self.allow_cli_args = False
            builtins.print = self.shell_print
            self.histfile = ".unpacker_history"
            self.clear_queue = False
            self.sample = None
            parser = argparse.ArgumentParser(
                prog='unipacker',
                description='Automatic and platform-independent unpacker for Windows binaries based on emulation')
            parser.add_argument('samples', metavar='sample', type=file_or_dir, nargs='*',
                                help='The path to a sample (or directory containing samples) you want unpacked')
            parser.add_argument('-d', '--dest', nargs='?', default='.',
                                help='The destination directory for unpacked binaries')
            parser.add_argument('-p', '--partition-by-packer', action='store_true',
                                help='Group the unpacked files by packer')
            parser.add_argument('-i', '--interactive', action='store_true',
                                help='Open the chosen sample(s) in the un{i}packer shell')

            args = parser.parse_args()
            if args.samples:
                samples = []
                for s in args.samples:
                    if os.path.exists(s):
                        samples.extend(Sample.get_samples(s, interactive=args.interactive))
                    else:
                        print(f"Path does not exist: {s}")
                if args.interactive:
                    while True:
                        self.sample_loop(samples)
                        self.shell_event.wait()
                        samples = None
                else:
                    IOHandler(samples, args.dest, args.partition_by_packer)
            else:
                while True:
                    self.sample_loop()
                    self.shell_event.wait()

        except EOFError:
            with open(f"{os.path.dirname(unipacker.__file__)}/fortunes") as f:
                fortunes = f.read().splitlines()
            print(f"\n\x1b[31m{choice(fortunes)}\x1b[0m\n")
            sys.exit(0)

    def shell_print(self, *args, **kwargs):
        kwargs["file"] = self.stdout
        _print(*args, **kwargs)

    def sample_loop(self, samples=None):
        known_samples = self.init_banner_and_history()
        if not samples:
            sample_path = self.get_path_from_user(known_samples)
            samples = Sample.get_samples(sample_path)
        for self.sample in samples:
            print(f"\nNext up: {self.sample}")
            with open(".unpacker_history", "w") as f:
                f.writelines(
                    "\n".join(sorted(set([f"{self.sample.unpacker.name};{self.sample.path}"] + known_samples[:-1]))))

            self.init_engine()

            with open(f"{os.path.dirname(unipacker.__file__)}/fortunes") as f:
                fortunes = f.read().splitlines()
            print(f"\n\x1b[31m{choice(fortunes)}\x1b[0m\n")
            self.cmdloop()
            if self.clear_queue:
                break

    def init_engine(self):
        self.started = False
        self.rules = None
        self.address = None
        self.shell_event = threading.Event()
        self.engine = UnpackerEngine(self.sample)
        self.engine.register_client(self)
        self.address_updated(self.sample.unpacker.startaddr)

    def get_path_from_user(self, known_samples):
        print("Your options for today:\n")
        lines = []
        for i, s in enumerate(known_samples):
            if s == "New sample...":
                lines += [(f"\t[{i}]", "\x1b[33mNew sample...\x1b[0m", "")]
            else:
                label, name = s.split(";")
                lines += [(f"\t[{i}]", f"\x1b[34m{label}:\x1b[0m", name)]
        print_cols(lines)
        print()

        while True:
            try:
                id = int(input("Enter the option ID: "))
            except ValueError:
                print("Error parsing ID")
                continue
            if 0 <= id < len(known_samples) - 1:
                path = known_samples[id].split(";")[1]
            elif id == len(known_samples) - 1:
                path = input("Please enter the sample path (single file or directory): ")
            else:
                print(f"Invalid ID. Allowed range: 0 - {len(known_samples) - 1}")
                continue
            if os.path.exists(path):
                return path
            else:
                print("Path does not exist")
                continue

    def init_banner_and_history(self):
        with open(f"{os.path.dirname(unipacker.__file__)}/banner") as f:
            print(f.read())
        if not os.path.exists(self.histfile):
            open(self.histfile, "w+").close()
        with open(self.histfile) as f:
            known_samples = f.read().splitlines()[:10] + ["New sample..."]
        return known_samples

    def emu_started(self):
        self.started = True

    def emu_paused(self):
        self.shell_event.set()

    def emu_resumed(self):
        pass

    def emu_done(self):
        self.started = False
        self.print_stats()
        print()
        self.shell_event.set()

    def address_updated(self, address):
        self.address = address
        self.prompt = f"\x1b[33m[0x{address:02x}]> \x1b[0m"

    def continue_emu(self, single_instruction=False):
        self.shell_event.clear()
        self.engine.resume(single_instruction)
        self.shell_event.wait()

    def try_parse_address(self, addr):
        if addr in self.engine.apicall_handler.hooks:
            return f"0x{addr:02x} ({self.engine.apicall_handler.hooks[addr]})"
        return f"0x{addr:02x}"

    def print_regs(self, args=None):
        reg_values = get_reg_values(self.engine.uc)

        if not args:
            regs = reg_values.keys()
        else:
            regs = map(lambda r: r.lower(), args)

        for reg in regs:
            print(f"{reg.upper()} = 0x{reg_values[reg]:02x}")

    def print_mem(self, base, num_elements, t="int", base_alias=""):
        if not base_alias:
            base_alias = f"0x{base:02x}"

        string = None
        if t == "str":
            string = get_string(base, self.engine.uc)
            t = "byte"
            num_elements = len(string)

        types = {
            "byte": ("B", 1),
            "int": ("<I", 4)
        }
        fmt, size = types[t]
        for i in range(num_elements):
            item, = struct.unpack(fmt, self.engine.uc.mem_read(base + i * size, size))
            print(f"{base_alias}+{i * 4} = 0x{item:02x}")

        if string is not None:
            print(f"String @0x{base:02x}: {string}")

    def print_stack(self, elements):
        esp = self.engine.uc.reg_read(UC_X86_REG_ESP)
        self.print_mem(self.engine.uc, esp, elements, base_alias="ESP")

    def print_imports(self, args):
        lines_static = []
        lines_dynamic = []

        for addr, name in self.engine.apicall_handler.hooks.items():
            try:
                module = self.engine.apicall_handler.module_for_function[name]
            except KeyError:
                module = "?"
            if name in self.sample.imports:
                lines_static += [(f"0x{addr:02x}", name, module)]
            else:
                lines_dynamic += [(f"0x{addr:02x}", name, module)]

        print("\n\x1b[31mStatic imports:\x1b[0m")
        print_cols(lines_static)
        print("\n\x1b[31mDynamic imports:\x1b[0m")
        print_cols(lines_dynamic)

    def print_stats(self):
        duration = time() - self.engine.start
        hours, rest = divmod(duration, 3600)
        minutes, seconds = divmod(rest, 60)
        print(f"\x1b[31mTime wasted emulating:\x1b[0m {int(hours):02} h {int(minutes):02} min {int(seconds):02} s")
        print("\x1b[31mAPI calls:\x1b[0m")
        print_cols([(name, amount) for name, amount in self.engine.apicall_counter.items()])
        print("\n\x1b[31mInstructions executed in sections:\x1b[0m")
        print_cols([(name, amount) for name, amount in self.engine.sections_executed.items()])
        print("\n\x1b[31mRead accesses:\x1b[0m")
        print_cols([(name, amount) for name, amount in self.engine.sections_read.items()])
        print("\n\x1b[31mWrite accesses:\x1b[0m")
        print_cols([(name, amount) for name, amount in self.engine.sections_written.items()])

    def do_aaa(self, args):
        """Analyze absolutely all: Show a collection of stats about the current sample"""
        print("\x1b[31mFile analysis:\x1b[0m")
        print_cols([
            ("YARA:", ", ".join(map(str, self.sample.yara_matches))),
            ("Chosen unpacker:", self.sample.unpacker.__class__.__name__),
            ("Allowed sections:", ', '.join(self.sample.unpacker.allowed_sections)),
            ("End of unpacking stub:",
             f"0x{self.sample.unpacker.endaddr:02x}" if self.sample.unpacker.endaddr != sys.maxsize else "unknown"),
            ("Section hopping detection:", "active" if self.sample.unpacker.section_hopping_control else "inactive"),
            ("Write+Exec detection:", "active" if self.sample.unpacker.write_execute_control else "inactive")
        ])
        print("\n\x1b[31mPE stats:\x1b[0m")
        print_cols([
            ("Declared virtual memory size:", f"0x{self.sample.virtualmemorysize:02x}", "", ""),
            ("Actual loaded image size:", f"0x{len(self.sample.loaded_image):02x}", "", ""),
            ("Image base address:", f"0x{self.sample.BASE_ADDR:02x}", "", ""),
            ("Mapped stack space:", f"0x{self.engine.STACK_ADDR:02x}", "-",
             f"0x{self.engine.STACK_ADDR + self.engine.STACK_SIZE:02x}"),
            ("Mapped hook space:", f"0x{self.engine.HOOK_ADDR:02x}", "-", f"0x{self.engine.HOOK_ADDR + 0x1000:02x}")
        ])
        self.do_i("i")
        print("\n\x1b[31mRegister status:\x1b[0m")
        self.do_i("r")

    def do_aaaa(self, args):
        """The version of aaa for people in a hurry: We know you don't want to waste your time staring at
boring static information. 'Auto-aaa' lets you get your hands dirty with emulation after
a quick glance at sample infos, without having to type 'r' yourself"""
        self.do_aaa(args)
        if any([self.engine.log_instr, self.engine.log_mem_read, self.engine.log_mem_write]):
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
                mem_targets += [(self.engine.STACK_ADDR, self.engine.STACK_ADDR + self.engine.STACK_SIZE)]
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
                if arg in self.engine.apicall_handler.hooks.values():
                    for addr, func_name in self.engine.apicall_handler.hooks.items():
                        if arg == func_name:
                            code_targets += [addr]
                            break
                else:
                    self.engine.apicall_handler.register_pending_breakpoint(arg)
            else:
                try:
                    code_targets += [int(arg, 0)]
                except ValueError:
                    print(f"Error parsing address {arg}")
        with self.engine.data_lock:
            self.engine.breakpoints.update(code_targets)
            self.engine.mem_breakpoints = list(merge(self.engine.mem_breakpoints + mem_targets))
            self.print_breakpoints()

    def print_breakpoints(self):
        current_breakpoints = list(map(self.try_parse_address, self.engine.breakpoints))
        current_breakpoints += list(map(lambda b: f'{b} (pending)', self.engine.apicall_handler.pending_breakpoints))
        print(f"Current breakpoints: {current_breakpoints}")
        current_mem_breakpoints = []
        for lower, upper in self.engine.mem_breakpoints:
            if lower == self.engine.STACK_ADDR and upper == self.engine.STACK_ADDR + self.engine.STACK_SIZE:
                current_mem_breakpoints += ["complete stack"]
            else:
                stack = lower >= self.engine.STACK_ADDR and upper <= self.engine.STACK_ADDR + self.engine.STACK_SIZE
                text = f"0x{lower:02x}" + (f" - 0x{upper:02x}" if upper != lower else "")
                current_mem_breakpoints += [text + (" (stack)" if stack else "")]
        print(f"Current mem breakpoints: {current_mem_breakpoints}")

    def do_c(self, args):
        """Continue emulation. If it hasn't been started yet, it will act the same as 'r'"""
        if self.started:
            self.continue_emu()
        else:
            print("Emulation not started yet. Starting now...")
            self.do_r(args)

    def do_hprint(self, args):
        """Print selected headers from the current sample

Usage:              hprint [HEADERS]
Headers:
    d,  dos         DOS header
    p,  pe          PE header
    o,  opt         Optional header
    s,  sections    Section table
    a,  all         All headers"""

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
                mapping[x](self.engine.uc, self.sample.BASE_ADDR)

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
            self.sample.unpacker.dump(self.engine.uc, self.engine.apicall_handler, self.sample, path=args)
        except OSError as e:
            print(f"Error dumping to {args}: {e}")

    def do_onlydmp(self, args):
        args = args or "dump"
        pe_write(self.engine.uc, self.sample.BASE_ADDR, self.sample.virtualmemorysize, args)

    def do_i(self, args):
        """Get status information

Show register values:       i r [reg names]
If no specific registers are provided, all registers are shown

Show imports:               i i
Static and dynamic imports are shown with their respective stub addresses in the loaded image"""
        info, *params = args.split(" ")
        mapping = {
            "r": self.print_regs,
            "registers": self.print_regs,
            "i": self.print_imports,
            "imports": self.print_imports
        }
        if info in mapping:
            mapping[info](params)
        else:
            print(f"Unrecognized info {info}")

    def do_x(self, args):
        """Dump memory at a specific address.

Usage:      x[/n] [{FORMAT}] LOCATION
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
                addr = get_reg_values(self.engine.uc)[alias]
            else:
                alias = ""
                addr = int(addr, 0)

            self.print_mem(addr, n, t, alias)
        except Exception as e:
            print(f"Error parsing command: {e}")

    def do_valset(self, args):
        """Set memory at a specific address to a custom value

Usage:      valset [{FORMAT}] OPERATION LOCATION
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
                old_value = get_reg_values(self.engine.uc)[reg]
                if op == "+=":
                    value += old_value
                elif op == "-=":
                    value -= old_value
                elif op == "*=":
                    value *= old_value
                elif op == "/=":
                    value = old_value // value
                self.engine.uc.reg_write(regs[reg], value)
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
                    old_value, = struct.unpack(fmt, self.engine.uc.mem_read(addr, size))
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
                self.engine.uc.mem_write(addr, to_write)
            except Exception as e:
                print(f"Error: {e}")

    def do_r(self, args):
        """Start execution"""
        if self.started:
            print("Emulation already started. Interpreting as 'c'")
            self.do_c(args)
            return
        self.shell_event.clear()
        threading.Thread(target=self.engine.emu).start()
        self.shell_event.wait()

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
        self.sample.unpacker.section_hopping_control = any(x in args for x in ["h", "hop"])
        print(f"[{'x' if self.sample.unpacker.section_hopping_control else ' '}] section hopping detection")
        self.sample.unpacker.write_execute_control = any(x in args for x in ["wx", "write_exec"])
        print(f"[{'x' if self.sample.unpacker.write_execute_control else ' '}] Write+Exec detection")

    def do_nxtsample(self, args):
        """Close the current sample and go to the next one (if available),
        or start at the initial file choosing prompt again."""
        if self.started:
            self.shell_event.clear()
            self.engine.stop()
        else:
            self.shell_event.set()
        print("")
        return True  # exits the cmd loop

    def do_rst(self, args):
        """Close the current sample but don't continue with the next one.
        If there are still samples in the queue, they are discarded."""
        self.clear_queue = True
        return self.do_nxtsample("")

    def do_s(self, args):
        """Execute a single instruction and return to the shell"""
        if self.started:
            self.continue_emu(single_instruction=True)
        else:
            print("Emulation not started yet. Starting now...")
            self.engine.single_instruction = True
            self.do_r(args)

    def do_del(self, args):
        """Removes breakpoints. Usage is the same as 'b', but the selected breakpoints and breakpoint ranges are being
deleted this time."""
        code_targets = []
        mem_targets = []
        if not args:
            self.engine.breakpoints.clear()
            self.engine.mem_breakpoints.clear()
            self.engine.apicall_handler.pending_breakpoints.clear()
        for arg in args.split(" "):
            if not arg:
                continue
            if arg == "stack":
                mem_targets += [(self.engine.STACK_ADDR, self.engine.STACK_ADDR + self.engine.STACK_SIZE)]
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
                if arg in self.engine.apicall_handler.hooks.values():
                    for addr, func_name in self.engine.apicall_handler.hooks.items():
                        if arg == func_name:
                            code_targets += [addr]
                            break
                elif arg in self.engine.apicall_handler.pending_breakpoints:
                    self.engine.apicall_handler.pending_breakpoints.remove(arg)
                else:
                    print(f"Unknown method {arg}, not imported or used in pending breakpoint")
            else:
                try:
                    code_targets += [int(arg, 0)]
                except ValueError:
                    print(f"Error parsing address {arg}")
        with self.engine.data_lock:
            for t in code_targets:
                try:
                    self.engine.breakpoints.remove(t)
                except KeyError:
                    pass
            new_mem_breakpoints = []
            for b_lower, b_upper in self.engine.mem_breakpoints:
                for t_lower, t_upper in mem_targets:
                    new_mem_breakpoints += remove_range((b_lower, b_upper), (t_lower, t_upper))
            self.engine.mem_breakpoints = list(merge(new_mem_breakpoints))
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
        self.engine.log_mem_read = any(x in args for x in ["r", "read"])
        print(f"[{'x' if self.engine.log_mem_read else ' '}] mem read")
        self.engine.log_mem_write = any(x in args for x in ["w", "write"])
        print(f"[{'x' if self.engine.log_mem_write else ' '}] mem write")
        self.engine.log_instr = any(x in args for x in ["i", "instr"])
        print(f"[{'x' if self.engine.log_instr else ' '}] instructions")
        self.engine.log_apicalls = any(x in args for x in ["s", "sys"])
        print(f"[{'x' if self.engine.log_apicalls else ' '}] API calls")

    def do_stats(self, args):
        """Print emulation statistics: In which section are the instructions located that were executed, which
sections have been read from and which have been written to"""
        self.print_stats()

    def do_yara(self, args):
        """Run YARA rules against the sample

Usage:          yara [<rules_path>]

If no rules file is specified, the default 'malwrsig.yar' is being used.
Those rules are then compiled and checked against the memory dump of the current emulator state (see 'dump' for further
details on this representation)"""
        if not args:
            if not self.rules:
                try:
                    self.rules = yara.compile(filepath=f"{os.path.dirname(unipacker.__file__)}/malwrsig.yar")
                    print("Default rules file used: malwrsig.yar")
                except:
                    print("\x1b[31mError: malwrsig.yar not found!\x1b[0m")
        else:
            self.rules = yara.compile(filepath=args)
        self.sample.unpacker.dump(self.engine.uc, self.engine.apicall_handler, self.sample)
        matches = self.rules.match("unpacked.exe")
        print(", ".join(map(str, matches)))

    def do_eof(self, args):
        """Exit un{i}packer by pressing ^D"""
        if self.started:
            self.shell_event.clear()
            self.engine.stop()
            self.shell_event.wait()
        with open(f"{os.path.dirname(unipacker.__file__)}/fortunes") as f:
            fortunes = f.read().splitlines()
        print("\n\x1b[31m" + choice(fortunes) + "\x1b[0m")
        self.exit_code = 0
        return super().do_eof(args)

    do_exit = do_eof


def main():
    Shell()


if __name__ == '__main__':
    main()
