import click
import os
import subprocess
import time
import crypto
import platform
import r2pipe
import hashlib
import sys
from datetime import datetime
from playsound import playsound
from colorama import Fore, Back, Style
from colorama import Fore, init
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from playsound import playsound
 
# for playing note.wav file

print('playing sound using  playsound')

@click.group()
def cli():
    pass
@cli.command()
def function1():
    ("Executing function 1: File Size") 
    print_file_size(input_file)
    Repeat(input_file)
def function2():
    print("Executing function 2: Read File")
    read_file(input_file)
    time.sleep(2)
    Repeat(input_file)
def function3():
    print("Executing function3: arch_detect and other info")
    print("Detection Results:")
    detect_arch(input_file)
    time.sleep(1)
    Repeat(input_file)
@cli.command()
def function4():
    print("Executing function4:File_conversion")
    file_extension = click.prompt("Enter the input file_extension")
    output_format = click.prompt("Enter the output format(ihex,elf32-i386,elf64-i386,binary,srec)")
    output_extension = click.prompt("Enter the output extension")
    file_extension_to_input_format(output_extension)
    run_objcopy(input_file, input_format,file_extension, output_format, output_extension)
    time.sleep(1)
    Repeat(input_file)
@cli.command()
def function5():
    print("Executing function4: Entropy Check")
    entropy_check(input_file)
    Repeat(input_file)
    time.sleep(1)
@cli.command()
def function6():
    print("2")
    print("Executing function 6: Decompile")
    architecture = input("Enter the architecture (e.g., x86, arm, mips): ").strip().lower()
    file_format = input("Enter the file format (e.g., elf, pe, mach0): ").strip()
   # input_file = input("Enter the input file path: ").strip()
    generate_radare2_command(architecture, file_format, input_file)
    run_radare2(input_file)
    time.sleep(1)
    Repeat(input_file)
@cli.command()
def function7():
    print("Executing function 7: Extracting the strings")
    extract_strings(input_file)
    time.sleep(1)
    Repeat(input_file)
@cli.command()
def function8():
    print("Executing function 8: Decompile")
    architecture = input("Enter the architecture (e.g., x86, arm, mips): ").strip().lower()
    file_format = input("Enter the file format (e.g., elf, pe, mach0): ").strip()
    input_file = input("Enter the input file path: ").strip()
    generate_radare2_command(architecture, file_format, input_file)
    run_radare2(input_file)
    time.sleep(1)
    Repeat(input_file)
@cli.command()
def function9():
    print("Executing function 9: Crypto_analyse")
    input_file = click.prompt("Enter the path of the input file")
    analyze_crypto(input_file)
    time.sleep(1)
    Repeat(input_file)
def function10():
    print("Executing function 10:emba:decompile")
    input_file = click.prompt("Enter the path of the input file")
    your_username= click.prompt('Please enter your username')
    run_emba(input_file,output_file,your_username)
    cve_file = "/home/pranav/Downloads/logs/emba_log.txt/s17_cwe_checker.txt"
    print("hi")
    cve_checker(cve_file)
    Repeat(input_file)
def function11():
    print("Executing function 11: Comparing_binaries")
    file1 = click.prompt("Enter the path of the input file1")
    file2 = click.prompt("Enter the path of the input file2")
    file_compare(file1,file2)
    time.sleep(1)
    Repeat(input_file)
def function12():
    print("file extraction")
    input_file1 = click.prompt("Enter the path of the input file")
    print_subchoices1()
    print("select Particular operation")
    fmk(input_file1)
    Repeat(input_file)
def function13():
    print("file repacking")
    input_directory = click.prompt("Enter the path of the input file directory")
    firmware_repack(input_directory)
    Repeat(input_file)
def print_choices():
    print(Fore.WHITE)
    print("Select Options to perform Operations:")
    print("1) File Size")
    print("2) File read")
    print("3) Architechure_detection")
    print("4) File conversion")
    print("5) Entropy Check")
    print("6) Disassembly")
    print("7) String extraction")
    print("8) Decompiler")
    print("9)Analysing_crypto_from function")
    print("10)Decompile and report generation with cve_scanning")
    print("11)comparing the binaries")
    print("12)Firmware unpacking")
    print("13)Firmware packing")
def print_file_size(input_file):
 file_size = os.path.getsize(input_file)
 print(Fore.RED)
 print(file_size)
 bytes_value = file_size
 def bytes_to_kb(bytes_value):
    return bytes_value / 1024
 def bytes_to_mb(bytes_value):
    return bytes_value / (1024 ** 2)
 kb_value = bytes_to_kb(bytes_value)
 mb_value = bytes_to_mb(bytes_value)
 print("Value in KB:", kb_value)
 print("Value in MB:", mb_value)
def read_file(input_file):
    f = open(input_file, mode="rb")
    print(Fore.RED+"--------------------------------------------------------------------RAW_BINARY-------------------------------------------------------------------------------------")
    try:
        print(Fore.RED)
        output = subprocess.check_output(["hexyl", input_file], universal_newlines=True)
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error running objcopy command:", e)
def file_extension_to_input_format(file_extension):
    if file_extension == 'bin':
        return 'binary'
    if file_extension == 'elf':
        return 'elf32-i386'
    if file_extension == 'elf':
        return 'elf32-i386'
    if file_extension == 'hex':
        return 'ihex'
    if file_extension == 's19':
        return 'srec'
def output_format_to_output_extension(output_format):
    if output_format == 'bin':
        return 'bin'
    if output_format == 'elf32-i386':
        return 'elf'
    if output_format == 'elf64-i386':
        return 'elf'
    if output_format == 'ihex':
        return 'hex'
    if output_format == 'srec':
        return 's19'
def run_objcopy(input_file, input_format,file_extension, output_format, output_extension):
    input_format=file_extension_to_input_format(file_extension)
    try:
        print(Fore.RED)
        current_datetime =datetime.now().strftime("%Y-%m-%d %H-%M")
        str_current_datetime = str(current_datetime)
        output_file = input_file.rsplit(".", 1)[0] + "." + output_extension
        output_file = "convertedbinary_"+str_current_datetime+"."+output_extension
        command = ["objcopy", "-I", input_format, "-O",output_format,input_file,output_file]
        subprocess.run(command, check=True)
        file_size = os.path.getsize(output_file)
        bytes_value = file_size
        def bytes_to_kb(bytes_value):
         return bytes_value / 1024
        def bytes_to_mb(bytes_value):
         return bytes_value / (1024 ** 2)
        kb_value = bytes_to_kb(bytes_value)
        mb_value = bytes_to_mb(bytes_value)
        print(f"Object copy operation completed successfully. Output file: {output_file}")
        print("Value in KB:", kb_value)
        print("Value in MB:", mb_value)
        print(bytes_value,"kb")
    except subprocess.CalledProcessError as e:
        print("Error running objcopy command:", e)
input_format = ["binary","ihex","elf","srec"]
file_extension = ["bin","hex","elf","s19"]
y = zip(input_format,file_extension)
input_format = file_extension_to_input_format(file_extension)
output_directory = "/home/pranav/emba_logs"
def run_emba(input_file, output_file,your_username):
    input_file = os.path.expanduser(input_file)
    output_file = os.path.expanduser(output_file)
    os.chdir(r"/home/pranav/emba")
  #  print("hi")
    emba_dir = "/home/pranav/emba"
    installer_script = os.path.join(emba_dir, "installer.sh")
    emba_executable = os.path.join(emba_dir, "emba")
    if not os.path.isdir(emba_dir):
        print(f"EMBA directory '{emba_dir}' does not exist. Please check your installation.")
        return
    if not os.path.isfile(installer_script):
        print(f"Installer script '{installer_script}' does not exist. Please check your installation.")
        return
    if not os.path.isfile(emba_executable):
        print(f"EMBA executable '{emba_executable}' does not exist. Please check your installation.")
        return
    os.chdir(emba_dir)
    print(f"Changed directory to {emba_dir}")
    output_file = os.path.expanduser(output_file)
    parts = input_file.split(os.sep)
    home_index = parts.index(your_username)
    relative_path = "../"+os.sep.join(parts[home_index+1:])
    print(relative_path)
    try:
        log_dir = os.path.join(os.path.dirname(output_file), "logs")  
        os.makedirs(log_dir, exist_ok=True)
        current_datetime =datetime.now().strftime("%Y-%m-%d %H-%M")
        str_current_datetime = str(current_datetime)
        log_file = os.path.join(log_dir, "emba_log.txt")
        command = ["sudo", "./emba", "-l", log_file, "-f",relative_path, "-p", "./scan-profiles/default-scan.emba"]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running emba command:", e)
output_file = "~/Downloads/ji.txt"
log_dir = os.path.join(os.path.dirname(output_file), "logs")

#cve_file = "/home/pranav/Downloads/logs/emba_log.txt/s17_cwe_checker.txt"
def cve_checker(cve_file):
    print("bye")
    print(Fore.RED)
    with open(cve_file) as f:
        data = f.read()
        print("------------------------------i'm here----------------------")
        print(data)
        time.sleep(4)
def entropy_check(input_file):
    print(Fore.WHITE)
    run_binwalk(input_file)
    Repeat(input_file)()
def print_subchoices1():
    print(Fore.WHITE)
    print("Select Options to perform Operations:")
    print("                 1)  single_squashfs")
    print("                 2)  Multiple_squashfs")
    subchoices1 = int(input("select option from given menu :"))
    time.sleep(0.8)
    if subchoices1 == 1:
     fmk(input_file)
     Repeat(input_file)()
    if subchoices1 == 2:
     fmk1(input_file)
     #function2()
     Repeat(input_file)()
def run_binwalk(input_file):
    try:
        print(Fore.RED)
        output = subprocess.check_output(["binwalk", "-E", input_file], universal_newlines=True)
        print("Entropy check output:")
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error running binwalk command:", e)
def run_binwalk1(input_file):
    try:
        print(Fore.RED)
        output = subprocess.check_output(["binwalk", "-M", input_file], universal_newlines=True)
        print("")
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error running binwalk command:", e)
def run_binwalk2(input_file):
    try:
        print(Fore.RED)
        output = subprocess.check_output(["binwalk", "-e", input_file], universal_newlines=True)
        print("")
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error running binwalk command:", e)
#------------------------------------------------------------------------------------------------------------#
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
crypto_keywords = ["crypt", "encrypt", "ENCRYPTION", "decrypt", "cipher", "hash", "key",
                   "ssid", "signature", "UUID", "digest", "block", "stream", "symmetric",
                   "asymmetric", "RSA", "AES", "DES", "MD5", "SHA", "ECDSA", "Diffie-Hellman",
                   "Elliptic_Curve", "PKCS", "PGP", "SSL", "TLS", "X.509", "HMAC", "CBC",
                   "ECB", "CTR", "GCM", "RC4", "Blowfish", "Twofish", "Salsa", "ChaCha",
                   "PBKDF", "KDF", "PRNG", "Random", "Entropy", "crypt", "encrypt", "decrypt",
                   "hash", "cipher", "AES", "SHA", "HSM", "base_64"]
def run_radare2(input_file):
    try:
        print("ji")
        current_datetime = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        output_file1 = f"/home/pranav/fev-bin-hammer/Assembly_{current_datetime}.txt"
        command = [
            "r2", "-AA", "-qc", f"e asm.bits=; aaa; pd 3000; e scr.interactive=true;v", input_file
        ]
        output = subprocess.run(command, capture_output=True, text=True, check=True).stdout
        print(output)
        with open(output_file1, "w") as f:
            f.write(output)
        strings_output = subprocess.check_output(["strings", input_file], universal_newlines=True)
        res = strings_output.split()
        lst = [x.lower() for x in res]
        lst1 = [x.lower() for x in crypto_keywords]
        a_set = set(lst)
        b_set = set(lst1)
        if (a_set & b_set):
            print(f"Found crypto-related keywords: {a_set & b_set}")
        else:
            print("No common crypto keywords found")
        print(f"Assembly code saved to '{output_file1}'")
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
def generate_radare2_command(architecture, file_format, input_file):
    if architecture.lower() not in SUPPORTED_ARCHITECTURES:
        raise ValueError(f"Unsupported architecture: {architecture}")
    print("After opening the disassembly convert it to interactive using shift+! and follow path view--->Decompile")
    time.sleep(3)
    command = ["r2", "-AA", "-qc", f"e asm.arch={architecture}; e asm.bits=32; aaa; pdc @3000; e scr.interactive=true; V", "-b", file_format, input_file]
    return command

def run_radare2(input_file):
    try:
        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_file = f"/home/pranav/fev-bin-hammer/Assembly_{current_datetime}.txt"
        command = generate_radare2_command("arm", "elf", input_file)
        subprocess.run(command, check=True)
        strings_output = subprocess.check_output(["strings", input_file], universal_newlines=True)
        strings = [s.lower() for s in strings_output.split()]
        common_keywords = set(strings).intersection(crypto_keywords)
        if common_keywords:
            print("Common keywords found:", common_keywords)
        else:
            print("No common keywords found")

        print(f"Assembly code saved to '{output_file}'.")
        return output_file
    except subprocess.CalledProcessError as e:
        print("Error running  command:", e)
def extract_strings(input_file):
    try:
         print(Fore.RED)
         current_datetime =datetime.now().strftime("%Y-%m-%d %H-%M-%S")
         str_current_datetime = str(current_datetime)
         output_file = "readbinarystings_"+str_current_datetime+".txt"
         strings_output = subprocess.check_output(["strings", input_file], universal_newlines=True)
         res = strings_output.split()
         lst = [x.lower() for x in res]
         lst1 = [x.lower() for x in crypto_keywords]
         with open(output_file, "w") as  f:
            f.write(output_file)
         a_set = set(lst)
         b_set = set(lst1)
         if (a_set & b_set):
            print(a_set & b_set)
         else:
            print("No common elements") 
         print(f"Printable strings extracted from '{input_file}' and saved to '{output_file}'.")
         print("If you want to edit the string pick the choice")
         answer = ''
         answer = click.prompt("Please enter 'yes' or 'no':")
         if answer == 'yes':
             Hex_editing = subprocess.check_output(["ghex", input_file], universal_newlines=True)
         if answer == 'no':
             time.sleep(1)
    except subprocess.CalledProcessError as e:
        print("Error running strings command:", e)
def analyze_crypto(input_file):
    r2 = None
    try:
        init(autoreset=True)
        r2 = r2pipe.open(input_file)

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
            "blowfish", "twofish", "salsa", "chacha", "pbkdf", "kdf", "prng", "random", "entropy", "hsm", "base_64","bh","BH"
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
        if crypto_functions:
            print(Fore.GREEN + "Cryptographic functions found:")
            for func in crypto_functions:
                print("- Function: {} (Address: {})".format(func["name"], hex(func["offset"])))
        else:
            print(Fore.YELLOW + "No cryptographic functions found.")
    except FileNotFoundError:
        print(Fore.RED + "ERROR: Cannot find in PATH")
    except Exception as e:
        print(Fore.RED + f"ERROR: {str(e)}")
    finally:
        if r2 is not None:
            r2.quit()
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return None
    except Exception as e:
        return str(e)
def detect_arch(input_file):
    try:
        r2_format_output = subprocess.check_output(["r2", "-q", "-c", "i~format", input_file], universal_newlines=True).strip()
        r2_arch_output = subprocess.check_output(["r2", "-q", "-c", "i~arch", input_file], universal_newlines=True).strip()
        r2_arch_detect_output = subprocess.check_output(["r2", "-q", "-c", "i", input_file], universal_newlines=True).strip()
        r2_architecture = 'arch not found'
        architecture_info = {'architecture': 'arch not found'}
        file_output = subprocess.check_output(["file", input_file], universal_newlines=True).strip()
        if 'ELF' in file_output:
            if 'x86-64' in file_output:
                architecture_info['architecture'] = 'x86-64'
            elif '32-bit' in file_output:
                architecture_info['architecture'] = 'x86'
            elif 'ARM' in file_output:
                architecture_info['architecture'] = 'ARM'
            elif 'MIPS' in file_output:
                architecture_info['architecture'] = 'MIPS'
        elif 'Intel hex' in file_output:
            architecture_info['architecture'] = 'Intel hex'
        elif 'Motorola S-Record' in file_output:
            architecture_info['architecture'] = 'Motorola S-Record'
        elif 'DOS/MBR boot sector' in file_output:
            architecture_info['architecture'] = 'DOS/MBR boot sector'
        elif 'ISO 9660 CD-ROM filesystem' in file_output:
            architecture_info['architecture'] = 'ISO 9660 CD-ROM'
        elif 'data' in file_output:
            architecture_info['architecture'] = 'arch not found'
        else:
            architecture_info['architecture'] = 'arch not found'
        binwalk_process = subprocess.Popen(["binwalk", "-e", input_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        binwalk_output, binwalk_error = binwalk_process.communicate()
        binwalk_output = binwalk_output.decode('utf-8') if binwalk_output else ""
        binwalk_error = binwalk_error.decode('utf-8') if binwalk_error else ""
        output = (
            f"{Fore.YELLOW}File: {input_file}{Style.RESET_ALL}\n\n"
            f"{Fore.CYAN}***** Detected Archive Format *****\n"
            f"{r2_format_output}\n\n"
            f"***** Detected Architecture *****\n"
            f"{r2_arch_output}\n"
            f"{Fore.GREEN}Architecture detected: { r2_arch_detect_output}, {architecture_info['architecture']}{Style.RESET_ALL}\n\n"
            f"{Fore.MAGENTA}*****Extraction Output *****\n"
            f"{binwalk_output}\n"
        )
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error running command:")
        print(e.output)

def parse_results(results):
    architecture_info = {}
    if 'file' in results:
        file_output = results['file']
        if 'ELF' in file_output:
            if 'x86-64' in file_output:
                architecture_info['architecture'] = 'x86-64'
            elif '32-bit' in file_output:
                architecture_info['architecture'] = 'x86'
            elif 'ARM' in file_output:
                architecture_info['architecture'] = 'ARM'
            elif 'MIPS' in file_output:
                architecture_info['architecture'] = 'MIPS'
        elif 'Intel hex' in file_output:
            architecture_info['architecture'] = 'Intel hex'
        elif 'Motorola S-Record' in file_output:
            architecture_info['architecture'] = 'Motorola S-Record'
        elif 'DOS/MBR boot sector' in file_output:
            architecture_info['architecture'] = 'DOS/MBR boot sector'
        elif 'ISO 9660 CD-ROM filesystem' in file_output:
            architecture_info['architecture'] = 'ISO 9660 CD-ROM'
        elif 'data' in file_output:
            architecture_info['architecture'] = 'arch not found'
        else:
            architecture_info['architecture'] = 'arch not found'
    if 'r2' in results:
        r2_output = results['r2']
        if 'arch' in r2_output:
            architecture_info['architecture'] = r2_output.split(':')[1].strip()
        else:
            architecture_info['architecture'] = 'arch not found'
    if 'rabin2' in results:
        found_arch = False
        for line in results['rabin2'].splitlines():
            if line.startswith('arch'):
                architecture_info['architecture'] = line.split()[1]
                found_arch = True
                break
        if not found_arch:
            architecture_info['architecture'] = 'arch not found'
    return architecture_info
def file_compare(file1,file2):
    try:
        command = ["vbindiff",file1,file2]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
     file_compare(file1,file2)
def run_ghidra(input_file):
    try:
        command = ["ghidra"]
        subprocess.run(command, check=True)
        sys.exit(1)

    except subprocess.CalledProcessError as e:
        print("Error running ghidra command:", e)

    run_ghidra(input_file)
def analyze_binary(input_file):
    architecture_info = {   "i386", "x86-64", "Alpha", "ARM", "arm", "AVR", "BPF", "MIPS", "PowerPC", "SPARC",
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
      "HT32FXX", "HT85FXX", "HT48FXX", "HT48RXX", "HT46RXX", "HT49RXFirmwareX", "HT82XX",
      "HT95XX", "HT68FXX", "HT66FXX", "HT32XX", "SM321", "SM323E", "SM324", "SM325",
      "SM330", "SM501", "SM502", "SM712", "SM722", "SM340", "SM350", "STM8", "RS14100",
      "RS13100", "Rabbit 2000", "Rabbit 3000", "Rabbit 4000", "Rabbit 5000", "Rabbit 6000",
      "RP2040", "RL78", "78K0R", "R8C", "M16C", "H8S", "H8", "H8/Super Low Power", "RH850",
      "RX", "SuperH", "V850", "R32C", "M32C", "M32R", "R6501", "R6511", "R8070", "C8051",
      "EFM8", "EFM32", "STM32", "SM2XX", "XMOS", "Z8", "Z180", "eZ8", "eZ80", "Z16", "XC800",
      "XE166", "TriCore", "XMC4000", "XMC1000", "MCS-48", "MCS-51", "MCS-96", "MCS-251",
      "MCS-196", "Mico8", "Mico32", "MAXQ", "Secure Micros", "ARM 922T", "MIPS 4kSD"}
    print(Fore.RED)
    def run_command(command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return None
        except Exception as e:
            return str(e)

    try:
        results = {}
        file_output = run_command(f'file {input_file}')
        if file_output:
            results['file'] = file_output
        r2_output = run_command(f'r2 -c "iI~arch" -qq {input_file}')
        if r2_output:
            results['r2'] = r2_output
        rabin2_output = run_command(f'rabin2 -I {input_file}')
        if rabin2_output:
            results['rabin2'] = rabin2_output

        if 'file' in results:
            file_output = results['file']
            if 'ELF' in file_output:
                if 'x86-64' in file_output:
                    architecture_info['architecture'] = 'x86-64'
                elif '32-bit' in file_output:
                    architecture_info['architecture'] = 'x86'
                elif 'ARM' in file_output:
                    architecture_info['architecture'] = 'ARM'
                elif 'MIPS' in file_output:
                    architecture_info['architecture'] = 'MIPS'
            elif 'Intel hex' in file_output:
                architecture_info['architecture'] = 'Intel hex'
            elif 'Motorola S-Record' in file_output:
                architecture_info['architecture'] = 'Motorola S-Record'
            elif 'DOS/MBR boot sector' in file_output:
                architecture_info['architecture'] = 'DOS/MBR boot sector'
            elif 'ISO 9660 CD-ROM filesystem' in file_output:
                architecture_info['architecture'] = 'ISO 9660 CD-ROM'
            elif 'data' in file_output:
                architecture_info['architecture'] = 'arch not found'
            else:
                architecture_info['architecture'] = 'arch not found'

        if 'r2' in results:
            r2_output = results['r2']
            if 'arch' in r2_output:
                architecture_info['architecture'] = r2_output.split(':')[1].strip()
            else:
                architecture_info['architecture'] = 'arch not found'

        if 'rabin2' in results:
            found_arch = False
            for line in results['rabin2'].splitlines():
                if line.startswith('arch'):
                    architecture_info['architecture'] = line.split()[1]
                    found_arch = True
                    break
            if not found_arch:
                architecture_info['architecture'] = 'arch not found'

        print(f"Architecture: {architecture_info['architecture']}")

    except Exception as e:
        print(f"Error analyzing binary: {e}")

def run_arch_detect(input_file):
    try:
        print(Fore.RED)
        command = ["r2", "-A", "-qc", f"e asm.arch=arm; e asm.bits=32; aaa; pd 3000", input_file]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running Radare2 command:", e)

def cve_checker123(log_file):
    with open(log_file, mode="rb") as f:
        data = f.read()
        print(data)

def fmk(input_file):
    os.chdir(r"/home/pranav/Downloads/firmware-mod-kit") 
    try:
        print(Fore.RED)
        command = ["./extract-firmware.sh", input_file]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
def fmk1(input_file):
    os.chdir(r"/home/pranav/Downloads/firmware-mod-kit") 
    try:
        print(Fore.RED)
        command = ["./extract-multisquashfs-firmware.sh", input_file]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
def firmware_repack(input_directory):
    os.chdir(r"/home/pranav/Downloads/firmware-mod-kit") 
    try:
        print(Fore.RED)
      #1
      #   print("hi")
        print(os.getcwd())
     #   command =["chmod +x ./build-firmware.sh"]
        command = ["bash", "./build-firmware.sh", input_directory]
        subprocess.run(command, check=True)
        #print(command)
      #  subprocess.run(command,check=True)
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)


def print_banner():
    banner = """
██████╗ ██╗███╗   ██╗      ██╗  ██╗ █████╗ ███╗   ███╗███╗   ███╗███████╗██████╗ 
██╔══██╗██║████╗  ██║      ██║  ██║██╔══██╗████╗ ████║████╗ ████║██╔════╝██╔══██╗
██████╔╝██║██╔██╗ ██║█████╗███████║███████║██╔████╔██║██╔████╔██║█████╗  ██████╔╝
██╔══██╗██║██║╚██╗██║╚════╝██╔══██║██╔══██║██║╚██╔╝██║██║╚██╔╝██║██╔══╝  ██╔══██╗
██████╔╝██║██║ ╚████║      ██║  ██║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║███████╗██║  ██║
╚═════╝ ╚═╝╚═╝  ╚═══╝      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝                                                                 
    """
    print(Fore.GREEN + banner)
def print_choices():
    print(Fore.WHITE)
    print("Select Options to perform Operations:")
    print("1) File Size")
    print("2) File read")
    print("3) Architecture detection")
    print("4) File conversion")
    print("5) Entropy Check")
    print("6) Disassembly")
    print("7) String extraction")
    print("8) Decompiler")
    print("9) Analyzing crypto from function")
    print("10) Decompile and report generation with CVE scanning")
    print("11) Comparing the binaries")
    print("12) Firmware unpacking")
    print("13) Firmware packing")

def file_check(input_file):
    check_file = os.path.isfile(input_file)
    if check_file:
       # print("file_exist")
        print_choices()
        choices = int(input("select option from given menu: "))
        execute_choice(choices, input_file)
    else:
        print("file not found")
        time.sleep(3)
        exit
def execute_choice(choices, input_file):
    if choices == 1:
        function1()
    elif choices == 2:
        function2()
    elif choices == 3:
        function3()
    elif choices == 4:
        function4()
    elif choices == 5:
        function5()
    elif choices == 6:
        function6()
    elif choices == 7:
        function7()
    elif choices == 8:
        function8()
    elif choices == 9:
        function9()
    elif choices == 10:
        function10()
    elif choices == 11:
        function11()
    elif choices == 12:
        function12()
    elif choices == 13:
        function13()
    else:
        print("invalid_selection, please select the choices between 1 to 13")
    time.sleep(2)
    Repeat(input_file)

def Repeat(input_file):
    print("--------------------------------------------------------------------------------------------------------------------------------------------------------")
    print_choices()
    choices = int(input("select option from given menu: "))
    execute_choice(choices, input_file)

if __name__ == "__main__":
    print_banner()
    while(1):
      input_file = click.prompt("Enter the path of the file:")
      file_check(input_file)
  
