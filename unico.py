from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import pefile
import os
import re
import sys
import struct
import socket

class Unico:
    STACK_LIMIT = 0x117d000
    STACK_BASE = 0x1180000
    HOOK_BASE = 0x2000000
    EXIT_ADDRESS = 0xfffff000
    IAT_ENTRIES = {}
    EIP_HOOKS = {}
    IAT_HOOKS = {}
    LAST_IAT_NAME = None

    def __init__(self):
        Unico.IAT_ENTRIES = {}
        Unico.EIP_HOOKS = {}
        Unico.IAT_HOOKS = {}
        Unico.LAST_IAT_NAME = None
        self.pe = None
        self.init_hooks = []
        self.add_default_hooks()
        self.add_socket_hooks()

    def add_default_hooks(self):
        def hook_GetModuleHandleW(uc, args):
            Unico.retn(uc, 4)
            return self.pe.OPTIONAL_HEADER.ImageBase

        def hook_strcpy(uc, args):
            addr_dst = int(args[0])
            addr_src = int(args[1])
            data = Unico.mem_read_cstr(uc, addr_src, include_null=True)
            uc.mem_write(addr_dst, data)
            Unico.log(uc, "IAT hook: strcpy 0x%x -> 0x%x %r" % (addr_src, addr_dst, data))
            return addr_dst

        def hook_memcpy(uc, args):
            addr_dst = int(args[0])
            addr_src = int(args[1])
            size = int(args[2])
            data = uc.mem_read(addr_src, size)
            uc.mem_write(addr_dst, data)
            Unico.log(uc, "IAT hook: memcpy 0x%x -> 0x%x %r" % (addr_src, addr_dst, data))
            return addr_dst

        def hook_memset(uc, args):
            addr_ptr = int(args[0])
            value = int(args[1])
            size = int(args[2])
            data = chr(value) * size
            uc.mem_write(addr_ptr, data)
            Unico.log(uc, "IAT hook: memset 0x%x 0x%x 0x%x" % (addr_ptr, value, size))
            return addr_ptr

        self.add_iat_hook('_initterm_e', lambda uc, args: 0)
        self.add_iat_hook('IsDebuggerPresent', lambda uc, args: 0)
        self.add_iat_hook('ExitProcess', Unico.stop)
        self.add_iat_hook('GetModuleHandleW', hook_GetModuleHandleW)

        self.add_iat_hook('strcpy', hook_strcpy)
        self.add_iat_hook('memcpy', hook_memcpy)
        self.add_iat_hook('memset', hook_memset)

    def add_socket_hooks(self):
        def hook_inet_addr(uc, args):
            addr_cp = int(args[0])
            cp = Unico.mem_read_cstr(uc, addr_cp)
            Unico.log(uc, "IAT hook: inet_addr %r" % cp)
            addr = 0
            for x in reversed(cp.split('.')):
                addr = (addr << 8) + int(x)
            return addr

        def hook_getaddrinfo(uc, args):
            addr_name = int(args[0])
            addr_service = int(args[1])
            name = Unico.mem_read_cstr(uc, addr_name)
            service = Unico.mem_read_cstr(uc, addr_service)
            Unico.log(uc, "IAT hook: getaddrinfo '%s:%s'" % (name, service))
            return 0

        def hook_gethostbyname(uc, args):
            addr_name = int(args[0])
            hostname = Unico.mem_read_cstr(uc, addr_name)
            Unico.log(uc, "IAT hook: gethostbyname '%s'" % hostname)

        def hook_htons(uc, args):
            arg = int(args[0])
            Unico.log(uc, "IAT hook: htons %d" % arg)
            return socket.htons(arg)

        def hook_bind(uc, args):
            addr_sockaddr = int(args[1])
            family, port, addr = struct.unpack('>HH4s', uc.mem_read(addr_sockaddr, 8))
            ipaddr = socket.inet_ntoa(addr)
            Unico.log(uc, "IAT hook: socket bind '%s:%d'" % (ipaddr, port))
            return 0

        def hook_connect(uc, args):
            addr_sockaddr = int(args[1])
            family, port, addr = struct.unpack('>HH4s', uc.mem_read(addr_sockaddr, 8))
            ipaddr = socket.inet_ntoa(addr)
            Unico.log(uc, "IAT hook: socket connect '%s:%d'" % (ipaddr, port))
            return 0

        def hook_WSASend(uc, args):
            addr_buf = int(args[1])
            length, addr_buf = struct.unpack('<II', uc.mem_read(addr_buf, 8))
            data = uc.mem_read(addr_buf, length)
            Unico.log(uc, "IAT hook: socket send %r" % str(data))
            return 0

        def hook_send(uc, args):
            addr_buf = int(args[1])
            length = int(args[2])
            data = uc.mem_read(addr_buf, length)
            Unico.log(uc, "IAT hook: socket send %r" % str(data))
            return length

        self.add_iat_hook('inet_addr', hook_inet_addr)
        self.add_iat_hook('getaddrinfo', hook_getaddrinfo)
        self.add_iat_hook('gethostbyname', hook_gethostbyname)
        self.add_iat_hook('htons', hook_htons)
        self.add_iat_hook('WSAbind', hook_bind)
        self.add_iat_hook('bind', hook_bind)
        self.add_iat_hook('WSAConnect', hook_connect)
        self.add_iat_hook('connect', hook_connect)
        self.add_iat_hook('WSASend', hook_WSASend)
        self.add_iat_hook('send', hook_send)

    def add_init_hook(self, handler):
        self.init_hooks.append(handler)

    def add_iat_hook(self, name, handler):
        """handler(uc, args)"""
        Unico.IAT_HOOKS[name] = handler

    def add_eip_hook(self, address, handler):
        """handler(uc, address, size)"""
        Unico.EIP_HOOKS[address] = handler

    @staticmethod
    def retn(uc, n):
        esp = uc.reg_read(UC_X86_REG_ESP)
        retaddr_mem = str(uc.mem_read(esp, 4))
        retaddr = struct.unpack('<I', retaddr_mem)[0]
        uc.mem_write(esp+n, retaddr_mem)
        uc.reg_write(UC_X86_REG_ESP, esp+n)

    @staticmethod
    def stop(uc, *args):
        uc.reg_write(UC_X86_REG_EIP, Unico.EXIT_ADDRESS)

    @staticmethod
    def skip(uc, address, size):
        return address + size

    @staticmethod
    def mem_read_cstr(uc, addr, include_null=False):
        data = uc.mem_read(addr, 8192)
        m = re.search(r'^[^\x00]*', str(data))
        cstr = m.group(0)
        if include_null:
            cstr += '\x00'
        return cstr

    @staticmethod
    def log(uc, message):
        print("[0x%x] %s" % (uc.reg_read(UC_X86_REG_EIP), message))

    @staticmethod
    def hook_code(uc, address, size, user_data):
        if address == Unico.HOOK_BASE + 4:
            ESP = uc.reg_read(UC_X86_REG_ESP)
            args = struct.unpack('<IIIIII', uc.mem_read(ESP+4, 24))
            ret = 1
            if Unico.LAST_IAT_NAME in Unico.IAT_HOOKS:
                try:
                    eax = Unico.IAT_HOOKS[Unico.LAST_IAT_NAME](uc, args)
                    if isinstance(eax, (int, long)):
                        ret = eax
                except Exception as e:
                    Unico.log(uc, "IAT hook error, name = %s, message = %s" % (Unico.LAST_IAT_NAME, e))
            uc.mem_write(Unico.HOOK_BASE, struct.pack('<I', ret))
            Unico.log(uc, "IAT function is being CALL, %s(%s) = 0x%x" % (Unico.LAST_IAT_NAME, ', '.join(map(hex, args)), ret))
        elif address in Unico.EIP_HOOKS:
            try:
                neweip = Unico.EIP_HOOKS[address](uc, address, size)
                if isinstance(neweip, (int, long)):
                    uc.reg_write(UC_X86_REG_EIP, neweip)
                    Unico.log(uc, "EIP hook at 0x%x (jump to 0x%x)" % (address, neweip))
                else:
                    Unico.log(uc, "EIP hook at 0x%x" % address)
            except Exception as e:
                Unico.log(uc, "EIP hook error, address = 0x%x, message = %s" % (address, e))
        elif address < 0x1000:
            Unico.log(uc, "EIP is on NULL page, exiting...")
            Unico.stop(uc)

    @staticmethod
    def hook_mem_access(uc, access, address, size, value, user_data):
        if access == UC_MEM_READ:
            if size == 4:
                data = uc.mem_read(address, size)
                value = struct.unpack('<I', data)[0]
                Unico.log(uc, "Memory is being READ at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
            else:
                Unico.log(uc, "Memory is being READ at 0x%x, data size = %u" % (address, size))
            if address in Unico.IAT_ENTRIES:
                Unico.LAST_IAT_NAME = Unico.IAT_ENTRIES[address]
        elif access == UC_MEM_WRITE:
            if address < 0x1000:
                print("\nWARNING: memory is being WRITE to NULL page, it may cause inaccurate results from here.\n")
            Unico.log(uc, "Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        elif access == UC_MEM_FETCH:
            Unico.log(uc, "Memory is being FETCH at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        else:
            raise Exception("Unexpected access type: %d" % access)

    @staticmethod
    def hook_mem_invalid(uc, access, address, size, value, user_data):
        if access == UC_MEM_READ_UNMAPPED:
            Unico.log(uc, "Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        elif access == UC_MEM_WRITE_UNMAPPED:
            Unico.log(uc, "Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        else:
            raise Exception("Unexpected access type: %d" % access)
        uc.mem_map(address & ~0xFFF, 0x1000)
        return True

    @staticmethod
    def hook_mem_fetch_unmapped(uc, access, address, size, value, user_data):
        Unico.log(uc, "Missing memory is being FETCH at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))

    def run(self, pe_file, addr_start, addr_end):
        with open(pe_file, 'rb') as f:
            PE_IMAGE = f.read()

        self.pe = pefile.PE(data=PE_IMAGE)

        IMAGE_BASE = self.pe.OPTIONAL_HEADER.ImageBase
        SIZE_OF_IMAGE = self.pe.OPTIONAL_HEADER.SizeOfImage
        ENTRY_POINT = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        try:
            mapped_image = self.pe.get_memory_mapped_image(ImageBase=IMAGE_BASE)
        except AttributeError:
            mapped_image = PE_IMAGE
        mapped_size = (len(mapped_image) + 0x1000) & ~0xFFF

        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(IMAGE_BASE, mapped_size)
        uc.mem_write(IMAGE_BASE, mapped_image)

        with open('pe_image_before.dump', 'wb') as f:
            f.write(uc.mem_read(IMAGE_BASE, mapped_size))

        uc.mem_map(self.STACK_LIMIT, self.STACK_BASE-self.STACK_LIMIT)
        uc.mem_write(self.STACK_LIMIT, '\xdd' * (self.STACK_BASE-self.STACK_LIMIT))

        uc.reg_write(UC_X86_REG_ESP, self.STACK_BASE-0x800)
        uc.reg_write(UC_X86_REG_EBP, self.STACK_BASE-0x400)

        uc.mem_map(Unico.HOOK_BASE, 0x1000)
        uc.mem_write(Unico.HOOK_BASE, '\x00\x00\x00\x00\x8b\x04\x25' + struct.pack('<I', Unico.HOOK_BASE) + '\xc3')  # mov eax, [HOOK_BASE]; ret

        print("[+] Listing the imported symbols")
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            print(entry.dll)
            for imp in entry.imports:
                print("  0x%x %s" % (imp.address, imp.name))
                uc.mem_write(imp.address, struct.pack('<I', Unico.HOOK_BASE+4))
                Unico.IAT_ENTRIES[imp.address] = imp.name
        print("")

        uc.hook_add(UC_HOOK_CODE, Unico.hook_code)
        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH, Unico.hook_mem_access)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, Unico.hook_mem_invalid)
        uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, Unico.hook_mem_fetch_unmapped)

        if not addr_start:
            addr_start = IMAGE_BASE + ENTRY_POINT

        if addr_end:
            Unico.EXIT_ADDRESS = addr_end
        else:
            addr_end = Unico.EXIT_ADDRESS
            uc.mem_map(Unico.EXIT_ADDRESS, 0x1000)
            uc.mem_write(uc.reg_read(UC_X86_REG_ESP), struct.pack('<I', addr_end))  # store addr_end as return address

        for init_hook in self.init_hooks:
            init_hook(uc)

        try:
            uc.emu_start(addr_start, addr_end)
        except UcError as e:
            print("ERROR: %s" % e)

        print("\n[+] Emulation done. Below is the CPU context")

        print(">>> EAX = 0x%x" % uc.reg_read(UC_X86_REG_EAX))
        print(">>> EBX = 0x%x" % uc.reg_read(UC_X86_REG_EBX))
        print(">>> ECX = 0x%x" % uc.reg_read(UC_X86_REG_ECX))
        print(">>> EDX = 0x%x" % uc.reg_read(UC_X86_REG_EDX))
        print(">>> ESI = 0x%x" % uc.reg_read(UC_X86_REG_ESI))
        print(">>> EDI = 0x%x" % uc.reg_read(UC_X86_REG_EDI))
        print(">>> ESP = 0x%x" % uc.reg_read(UC_X86_REG_ESP))
        print(">>> EBP = 0x%x" % uc.reg_read(UC_X86_REG_EBP))
        print(">>> EIP = 0x%x" % uc.reg_read(UC_X86_REG_EIP))

        print("\n[+] Write out pe_image.diff and stack.dump")

        with open('pe_image_after.dump', 'wb') as f:
            f.write(uc.mem_read(IMAGE_BASE, mapped_size))

        with open('stack.dump', 'wb') as f:
            f.write(uc.mem_read(self.STACK_LIMIT, self.STACK_BASE-self.STACK_LIMIT))

        os.system("bash -c 'diff -u <(xxd pe_image_before.dump) <(xxd pe_image_after.dump) >pe_image.diff'")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python %s PE_FILE [ADDR_START ADDR_END]" % sys.argv[0], file=sys.stderr)
        sys.exit(1)

    pe_file = sys.argv[1]
    addr_start = int(sys.argv[2], 16) if len(sys.argv) >= 3 else None
    addr_end = int(sys.argv[3], 16) if len(sys.argv) >= 4 else None

    unico = Unico()
    unico.run(pe_file, addr_start, addr_end)
