import os
import r2pipe
from colorama import Fore, init

def analyze_crypto(input_file, output_file):
    r2 = None
    try:
        # Initialize colorama
        init(autoreset=True)

        # Set the path to radare2
        radare2_path = "/home/pranav/radare2"  # Replace with the actual path to Radare2
        os.environ["PATH"] += os.pathsep + radare2_path

        # Open the binary in Radare2
        r2 = r2pipe.open(input_file)
        
        # Apply relocations
        r2.cmd("-e bin.relocs.apply=true")
        
        # Analyze the binary
        r2.cmd("aaa")

        # List all functions in the binary
        functions = r2.cmdj("aflj")

        if not functions:
            print("No functions found in the binary.")
            return

        # Keywords indicating cryptographic operations
        crypto_keywords = [
            "crypt", "encrypt", "decrypt", "cipher", "hash", "key", "ssid", "signature", "digest", "block", 
            "stream", "symmetric", "asymmetric", "rsa", "aes", "des", "md5", "sha", "ecdsa", "diffie-hellman", 
            "elliptic_curve", "pkcs", "pgp", "ssl", "tls", "x.509", "hmac", "cbc", "ecb", "ctr", "gcm", "rc4", 
            "blowfish", "twofish", "salsa", "chacha", "pbkdf", "kdf", "prng", "random", "entropy", "hsm", "base_64"
        ]

        # Convert all crypto keywords to lowercase
        crypto_keywords = [keyword.lower() for keyword in crypto_keywords]

        # Initialize a list to store cryptographic functions
        crypto_functions = []

        # Iterate through each function to identify cryptographic functions
        for func in functions:
            for keyword in crypto_keywords:
                if keyword in func["name"].lower():
                    crypto_functions.append(func)
                    break  # Move to the next function once a keyword is found

        # Print the identified cryptographic functions
        if crypto_functions:
            print(Fore.GREEN + "Cryptographic functions found:")
            for func in crypto_functions:
                print("- Function: {} (Address: {})".format(func["name"], hex(func["offset"])))
        else:
            print(Fore.YELLOW + "No cryptographic functions found.")

        # Write the functions to the output file
        with open(output_file, "w") as f:
            for func in functions:
                f.write(f"{func}\n")

    except FileNotFoundError:
        print(Fore.RED + "ERROR: Cannot find radare2 in PATH")
    except Exception as e:
        print(Fore.RED + f"ERROR: {str(e)}")
    finally:
        # Close Radare2 if it was opened successfully
        if r2 is not None:
            r2.quit()

# Example usage:
# analyze_crypto("/path/to/binary", "/path/to/output_file")

input_file='/home/pranav/fev-bin-hammer/test_binaries/APT_IVN.elf'
output_file='esd.txt'
analyze_crypto(input_file, output_file)
# Example usage:
# analyze_crypto("/path/to/binary", "/path/to/output_file")
