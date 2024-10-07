import subprocess
from datetime import datetime
import time
from colorama import Fore

crypto_keywords = ["crypt", "encrypt", "ENCRYPTION", "decrypt", "cipher", "hash", "key", "ssid", "signature", "UUID", "digest", "block", "stream", "symmetric", "asymmetric", "RSA", "AES", "DES", "MD5", "SHA", "ECDSA", "Diffie-Hellman", "Elliptic_Curve", "PKCS", "PGP", "SSL", "TLS", "X.509", "HMAC", "CBC", "ECB", "CTR", "GCM", "RC4", "Blowfish", "Twofish", "Salsa", "ChaCha", "PBKDF", "KDF", "PRNG", "Random", "Entropy", "crypt", "encrypt", "decrypt", "hash", "cipher", "AES", "SHA", "HSM", "base_64"]

def generate_radare2_command(architecture, file_format, input_file):
    SUPPORTED_ARCHITECTURES = [
        "i386", "x86-64", "Alpha", "ARM", "arm", "AVR", "BPF", "MIPS", "PowerPC", "SPARC",
        "RISC-V", "SH", "m68k", "S390", "XCore", "CR16", "HPPA", "ARC", "Blackfin",
        "Z80", "H8/300", "V810", "PDP11", "m680x", "V850", "CRIS", "XAP (CSR)", "PIC",
        "LM32", "8051", "6502", "i4004", "i8080", "Propeller", "EVM", "OR1K", "Tricore",
        "CHIP-8", "LH5801", "T8200", "GameBoy", "SNES", "SPC700", "MSP430", "Xtensa",
        "xcore", "NIOS II", "Java", "Dalvik", "Pickle", "WebAssembly", "MSIL", "EBC",
        "TMS320 (c54x, c55x, c55+, c64x)", "Hexagon", "Brainfuck", "Malbolge",
        "whitespace", "DCPU16", "LANAI", "lm32", "MCORE", "mcs96", "RSP", "SuperH-4",
        "VAX", "KVX", "Am29000", "LOONGARCH", "JDH8", "s390x", "STM8",
        "Nios II", "Nios 16-bit", "Blackfin", "SHARC", "TigerSHARC", "ADSP-21xx",
        "MicroConverter Family", "AT89 series", "AT90", "ATtiny", "ATmega", "ATxmega",
        "AT91SAM", "AVR32", "MARC4", "PSoC", "CY8C2xxxx", "CY8C3xxxx", "CY8C4xxxx",
        "CY8C5xxxx", "EM78PXXX Low Pin-Count MCU Family", "EM78PXXX GPIO Type MCU Family",
        "EM78PXXXN ADC Type MCU Family", "S1C6x family", "S1C88 family", "S1C17 family",
        "S1C33 family", "ESP8266", "ESP32", "ESP32C2", "ESP32C3", "ESP32C6", "ESP32H2",
        "Freescale S08", "Freescale S12", "Freescale Kinetis", "Freescale 683XX",
        "MCF5xxx", "M·CORE", "MPC500", "MPC 860", "MPC 8240", "MPC 8540", "MPC 5554",
        "HT32FXX", "HT85FXX", "HT48FXX", "HT48RXX", "HT46RXX", "HT49RXX", "HT82XX",
        "HT95XX", "HT68FXX", "HT66FXX", "HT32XX", "SM321", "SM323E", "SM324", "SM325",
        "SM330", "SM501", "SM502", "SM712", "SM722", "SM340", "SM350", "STM8", "RS14100",
        "RS13100", "Rabbit 2000", "Rabbit 3000", "Rabbit 4000", "Rabbit 5000", "Rabbit 6000",
        "RP2040", "RL78", "78K0R", "R8C", "M16C", "H8S", "H8", "H8/Super Low Power", "RH850",
        "RX", "SuperH", "V850", "R32C", "M32C", "M32R", "R6501", "R6511", "R8070", "C8051",
        "EFM8", "EFM32", "STM32", "SM2XX", "XMOS", "Z8", "Z180", "eZ8", "eZ80", "Z16", "XC800",
        "XE166", "TriCore", "XMC4000", "XMC1000", "MCS-48", "MCS-51", "MCS-96", "MCS-251",
        "MCS-196", "Mico8", "Mico32", "MAXQ", "Secure Micros", "ARM 922T", "MIPS 4kSD",
    ]

    # Validate architecture
    if architecture.lower() not in SUPPORTED_ARCHITECTURES:
        raise ValueError(f"Unsupported architecture: {architecture}")
       #! print("After opening the interctive view follow path view--->Decompile")
    # Create the command with user-specified architecture, file format, and family
    print("After opening the interctive view follow path view--->Decompile")
    command = ["r2", "-AA", "-qc", f"e asm.arch={architecture}; e asm.bits=32; aaa; pdc @3000; e scr.interactive=true; V", "-b", file_format, input_file]
    return command

def run_radare2(input_file):
    try:
        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_file = f"/home/pranav/fev-bin-hammer/Assembly_{current_datetime}.txt"
        
        command = generate_radare2_command("arm", "elf", input_file)
        subprocess.run(command, check=True)

        # Read and analyze strings from input file
        strings_output = subprocess.check_output(["strings", input_file], universal_newlines=True)
        strings = [s.lower() for s in strings_output.split()]

        # Check for common elements between strings and crypto keywords
        common_keywords = set(strings).intersection(crypto_keywords)
        if common_keywords:
            print("Common keywords found:", common_keywords)
        else:
            print("No common keywords found")

        print(f"Assembly code saved to '{output_file}'.")
        return output_file

    except subprocess.CalledProcessError as e:
        print("Error running Radare2 command:", e)

# Example usage:
if __name__ == "__main__":
    input_file = "/home/pranav/fev-bin-hammer/test_binaries/APT_IVN.elf"
    run_radare2(input_file)
