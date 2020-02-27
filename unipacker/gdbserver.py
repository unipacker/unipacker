import re
import socket
import struct
import threading
from binascii import hexlify
from time import sleep

from unipacker.utils import get_reg_values


class PacketParseError(Exception):
    pass


packet_pattern = re.compile(rb"\$(?P<data>.+)#(?P<checksum>..)")


def encode_data(data: bytes) -> bytes:
    escaped = b""
    for b in data:
        if b in b"#$}":
            escaped += b"}"
            b ^= 0x20
        escaped += bytes([b])
    return escaped


def decode_data(data: bytes) -> bytes:
    unescaped = b""
    escaped = False
    for b in data:
        if escaped:
            unescaped += bytes([b ^ 0x20])
            escaped = False
        else:
            if b == 0x7d:  # }
                escaped = True
            else:
                unescaped += bytes([b])
    return unescaped


def checksum(data: bytes) -> int:
    return sum(data) & 0xff


def generate_packet(data: bytes) -> bytes:
    return b"$" + encode_data(data) + b"#" + f"{checksum(data):02x}".encode()


def parse_packet(packet: bytes) -> bytes:
    match = packet_pattern.match(packet)
    if not match:
        raise PacketParseError("Incorrect format")
    data = match.group("data")
    expected_checksum = checksum(data)
    actual_checksum = int(match.group("checksum"), 16)
    if expected_checksum != actual_checksum:
        raise PacketParseError(f"Checksum mismatch: expected {hex(expected_checksum)}, got {hex(actual_checksum)}")
    return match.group("data")


def receive(conn: socket.socket, start="", until="") -> bytes:
    done = False
    out = conn.recv(1)
    while not done:
        buf = conn.recv(1)
        if buf != b"":
            out += buf
        else:
            done = True
        if out.endswith(until.encode()):
            done = True
    if start.encode() in out:
        return out[out.index(start.encode()):]
    return out


class GdbServer(object):

    def __init__(self, shell, port: int):
        self.shell = shell
        self.port = port
        self.running = False
        self.halt_cause = None
        self.handlers = {
            b"?": self.handle_halt_reason,
            b"c": self.handle_continue,
            b"s": self.handle_step,
            b"q": self.handle_general_query,
            b"m": self.handle_read_mem,
            b"M": self.handle_write_mem,
            b"g": self.handle_read_reg,
            b"G": self.handle_write_reg,
            b"X": self.handle_load_binary_data,
            b"z": self.handle_clear_breakpoint,
            b"Z": self.handle_set_breakpoint,
            b"H": self.handle_thread_ops,
            b"D": self.handle_detach
        }

    def start(self):
        threading.Thread(target=self.server_loop).start()

    def handle_detach(self, args: bytes) -> bytes:
        self.running = False
        return b"OK"

    def handle_general_query(self, args: bytes):
        if args.startswith(b"Supported"):
            return b"PacketSize=4096"
        elif args.startswith(b"Attached"):
            return b"0"  # we created the program on our own instead of attaching
        elif args.startswith(b"Offsets"):
            return b"Text=0;Data=0;Bss=0;"

    def handle_halt_reason(self, args: bytes) -> bytes:
        if self.halt_cause is None:
            return b"S05"  # SIGTRAP
        ret = self.halt_cause
        self.halt_cause = None
        return ret

    def handle_thread_ops(self, args: bytes) -> bytes:
        return b"OK"

    def handle_continue(self, args: bytes):
        # TODO continue at addr
        self.shell.do_c("")
        return b"S05"

    def handle_step(self, args: bytes):
        # TODO step at addr
        self.shell.do_s("")
        return b"S05"

    def handle_read_mem(self, args: bytes) -> bytes:
        addr, size = args.split(b",")
        addr = int(addr, 16)
        size = int(size)
        for start, end in sorted(map(lambda x: (x[0], x[1]), self.shell.engine.uc.mem_regions())):
            if start <= addr <= end:
                return hexlify(self.shell.engine.uc.mem_read(addr, size))
        return b""

    def handle_write_mem(self, args: bytes) -> bytes:
        addr, rest = args.split(b",")
        size, data = rest.split(b":")
        addr = int(addr, 16)
        size = int(size)
        map_upper = None
        for start, end in sorted(map(lambda x: (x[0], x[1]), self.shell.engine.uc.mem_regions())):
            if start <= addr <= end:
                map_upper = end
        if map_upper is None:
            self.shell.engine.uc.mem_map(addr, size)
        elif addr + size > map_upper:
            self.shell.engine.uc.mem_map(map_upper, addr + size - map_upper)
        self.shell.engine.uc.mem_write(addr, data)
        return b"OK"

    def handle_read_reg(self, args: bytes) -> bytes:
        regs = get_reg_values(self.shell.engine.uc)
        ret = b""
        for name, r in regs.items():
            ret += hexlify(struct.pack("<L", r))

        return ret

    def handle_write_reg(self, args: bytes) -> bytes:
        pass

    def handle_load_binary_data(self, args: bytes) -> bytes:
        pass

    def handle_clear_breakpoint(self, args: bytes) -> bytes:
        pass

    def handle_set_breakpoint(self, args: bytes) -> bytes:
        pass

    def client_loop(self, conn: socket.socket):
        last_packet = b""
        while self.running:
            packet = receive(conn, "$", "#")
            if packet.endswith(b"#"):
                packet += conn.recv(2)
            elif packet == b"-":
                # resend requested
                print(f"IN : {packet}")
                print(f"OUT: {last_packet}")
                conn.sendall(last_packet)
                continue
            elif not packet or packet == b"+":
                continue
            print(f"IN : {packet}")
            try:
                data = parse_packet(packet)
            except PacketParseError:
                print("Parse error")
                conn.sendall(b"-")
                continue
            conn.sendall(b"+")
            print("OUT: +")
            command = bytes([data[0]])
            if command in self.handlers:
                response = self.handlers[command](data[1:])
                if response is None:
                    response = b""
                last_packet = generate_packet(response)
            else:
                last_packet = generate_packet(b"")
            conn.sendall(last_packet)
            print(f"OUT: {last_packet}")

    def server_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        success = False
        while not success:
            try:
                sock.bind(("", self.port))
                success = True
            except socket.error:
                print(f"Binding GDB server on port {self.port} failed")
                sleep(5)
        sock.listen(1)
        print(f"GDB server ready on port {self.port}")
        self.running = True

        while self.running:
            conn, addr = sock.accept()
            print(f"Connected to client at {addr[0]}:{addr[1]}")
            try:
                self.client_loop(conn)
            finally:
                conn.close()
        sock.close()
