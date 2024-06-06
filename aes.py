import click
import os
import subprocess
import time
import crypto
import platform
#import angr
import r2pipe
import hashlib
import sys
from datetime import datetime
from playsound import playsound
from colorama import Fore, Back, Style
# for playing note.mp3 file

#from Crypto.Cipher import AES, DES
#from Crypto.Hash import SHA1, SHA256, MD5
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#from pyhidra import HidraController
#from pyhidra.util import DecompilationOptions

@click.group()
def cli():
    pass
@cli.command()
def function1():
    print("Executing function 1: File Size") 
    print_file_size(input_file)
   # Repeat()
    #time.sleep(1)
def function2():
    print("Executing function 2: Read File")
    #file_path = click.prompt("Enter the path of the file")
    read_file(input_file)
    time.sleep(2)
   # Repeat()
    #print_file_size(file_path)
def function3():
    print("Executing function3: r2ghidra_arch_detect")
    run_arch_detect(input_file)
    #arch_details(input_file)
    time.sleep(1)
@cli.command()
def function4():
    print("Executing function4: Object Copy")
    #print("file_extension:"+file_extension)
    file_extension = click.prompt("Enter the input file_extension")
    output_format = click.prompt("Enter the output format(ihex,elf32-i386,elf64-i386,binary,srec)")
    output_extension = click.prompt("Enter the output extension")
    #for output_format, output_extension in zip(output_formats, output_extensions):
     #run_objcopy(input_file, input_format, output_format, output_extension)
    file_extension_to_input_format(output_extension)
     #output_format_to_output_extension(output_format)
    run_objcopy(input_file, input_format,file_extension, output_format, output_extension)
       #print(output_file)
    time.sleep(1)
@cli.command()
def function5():
    print("Executing function4: Entropy Check")
    print_subchoices()
    Repeat()
    time.sleep(1)
@cli.command()
@click.option('--input_file', prompt='Enter the path of the input file')
#@click.option('--output_file', prompt='Enter the path of the output file')
def function6():
    print("Executing function 6: Radare2")
    #generate_radare2_command(architecture,file_format,family,input_file)
    #generate_radare2_command(architecture,file_format,family,input_file)
    #generate_radare2_command(architechure, file_format,family,input_file)
    #run_radare2(input_file)
    input_file =click.prompt("enter the path of input file")
    architecture = click.prompt("Enter the arch of the input file1")
    file_format = click.prompt("Enter the file format of input_file(bin,hex,elf,s19 etc.)")
    family = click.prompt("Enter the family of the controller/processor)")
    generate_radare2_command(architecture, file_format,family,input_file)
    Repeat()
   # time.sleep(1)
@cli.command()
def function7():
    print("Executing function 7: Cryptographic Operations Detection")
    #file_path = click.prompt("Enter the path of the file")
    detect_cryptographic_operations(input_file)
    #input_file = click.prompt("Enter the path of the input file")
    #output_file = click.prompt("Enter the path of the output file")
   # extract_strings(input_file)
    time.sleep(1)
    Repeat()
def function8():
    print("Executing function 8: Extracting the strings")
    #file_path = click.prompt("Enter the path of the file")
    extract_strings(input_file)
    #stringtocrypto(output_file)
    time.sleep(1)
    Repeat()
@cli.command()
def function9():
    print("Executing function 9: ghidra")
    #input_file = click.prompt("Enter the path of the input file")
    run_ghidra(input_file)
    time.sleep(1)
    Repeat()
@cli.command()
def function10():
    print("Executing function 10: Crypto_analyse")
    input_file = click.prompt("Enter the path of the input file")
    analyze_crypto(input_file)
    time.sleep(1)
    Repeat()
def function11():
    print("Executing function 11:emba:decompile")
    input_file = click.prompt("Enter the path of the input file")
    your_username= click.prompt('Please enter your username')
    run_emba(input_file,output_file,your_username)
    #with open("uui123.py") as file:
     #Yoexec(file.read())
    #cve_checker(log_file)
    Repeat()
def function12():
    print("Executing function 12: Comparing_binaries")
    file1 = click.prompt("Enter the path of the input file1")
    file2 = click.prompt("Enter the path of the input file2")
  #  output_file = click.prompt("Enter the path of the output file")
    file_compare(file1,file2)
    time.sleep(1)
    Repeat()
def function13():
    print("firmware `unpacking`")
    input_file = click.prompt("Enter the path of the input file")
    print_subchoices1()
    print("select Particular operation")

    fmk(input_file)
def function14():
    print("file repacking")
    time.sleep(2)
    print("file repacking is mostly supported by the file unpack by this tool similar tools used for binary packing.This is not useful for other file formats like word,docs,PE.")
    input_directory = click.prompt("Enter the path of the input file directory")
    firmware_repack(input_directory)
def print_choices():
    print(Fore.BLUE)
    print("Select Options to perform Operations:")
    print("1) File Size")
    print("2) File read")
    print("3) Architechure_detection")
    print("4) File conversion")
    print("5) Multiple operations")
    print("6) Disassembly")
    print("7) Cryptographic Operations Detection")
    print("8) String extraction")
    print("9) Decompiler")
    print("10)Analysing_crypto_from function")
    print("11)Decompile and report generation with cve_scanning")
    print("12)comparing the binaries")
    print("13)Firmware unpacking")
    print("14)Firmware packing")
def print_file_size(input_file):
 #f = open(input_file, mode="rb")
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
    try:#output_file = "convertedbinary_"+str_current_datetime+"."+output_extension
        print(Fore.RED)
        output = subprocess.check_output(["hexyl", input_file], universal_newlines=True)
        print(output)
        #command = ["objcopy", "-I", input_format, "-O", output_format, input_file, output_file]
        #subprocess.run(command, check=True)
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
    #file_extension = os.path.splitext(input_file)
    input_format=file_extension_to_input_format(file_extension)
    try:#output_file = "convertedbinary_"+str_current_datetime+"."+output_extension
        print(Fore.RED)
        output_file = input_file.rsplit(".", 1)[0] + "." + output_extension
        output_file = "convertedbinary_"+str_current_datetime+"."+output_extension
        command = ["objcopy", "-I", input_format, "-O",output_format,input_file,output_file]
        subprocess.run(command, check=True)
        file_size = os.path.getsize(output_file)
        bytes_value = file_size/1024
        #command = ["objcopy", "-I", input_format, "-O", output_format, input_file, output_file]
        #subprocess.run(command, check=True)
        print(f"Object copy operation completed successfully. Output file: {output_file}")
        print(bytes_value,"kb")
    except subprocess.CalledProcessError as e:
        print("Error running objcopy command:", e)
#output_formats = ["binary","elf32-i386", "elf64-i386","ihex","srec"]
#output_extensions = ["bin","elf","elf", "hex","s19"]
#x = zip(output_formats, output_extensions)
input_format = ["binary","ihex","elf","srec"]
file_extension = ["bin","hex","elf","s19"]
y = zip(input_format,file_extension)
input_format = file_extension_to_input_format(file_extension)
#input_format = file_extension_to_input_format(file_extension)
output_directory = "/home/pranav/emba_logs"
#input_file1 = "~/Downloads/application.hex"
def run_emba(input_file, output_file,your_username):
    input_file = os.path.expanduser(input_file)
    output_file = os.path.expanduser(output_file)
    os.chdir(r"/home/pranav/emba")
    output_file = os.path.expanduser(output_file)
    parts = input_file.split(os.sep)
    home_index = parts.index(your_username)
    relative_path = "../"+os.sep.join(parts[home_index+1:])
    print(relative_path)  # Change directory to where the emba executable is located
    try:
        log_dir = os.path.join(os.path.dirname(output_file), "logs")  # Create log directory in the same directory as output_file
        os.makedirs(log_dir, exist_ok=True)
        current_datetime =datetime.now().strftime("%Y-%m-%d %H-%M")
        str_current_datetime = str(current_datetime)
        #log_file = os.path.join(log_dir, "emba_log"+str_current_datetime+".txt")
        log_file = os.path.join(log_dir, "emba_log.txt")
        # Convert log file path to absolute path
        log_file = os.path.abspath(log_file)
        command = ["sudo", "./emba", "-l", log_file, "-f",relative_path, "-p", "./scan-profiles/default-scan.emba"]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running emba command:", e)
output_file = "~/home/pranav/fev-bin-hammer/ji.txt"
log_dir = os.path.join(os.path.dirname(output_file), "logs")
log_file = os.path.join(log_dir, "emba_log.txt")
#run_emba(input_file, output_file,your_username)
#print("---------------------------cve_checker-----------------------------------------")
cve_file = "/home/pranav/fev-bin-hammer/logs/emba_log.txt/s17_cwe_checker.txt"
def cve_checker(cve_file):
    print(Fore.RED)
    with open(cve_file) as f:
        data = f.read()
        print(data)
    cve_checker(cve_file)
# Example usage:
#def run_binwalk(input_file):
def print_subchoices():
    print(Fore.BLUE)
    print("Select Options to perform Operations:")
    print("                 1)  entropy check")
    print("                 2)  scan extracted files")
    print("                 3)  arch")
    subchoices = int(input("select option from given menu :"))
    if subchoices == 1:
     run_binwalk(input_file)
     Repeat()
    if subchoices == 2:
     run_binwalk1(input_file)
     Repeat()
    if subchoices == 3:
     run_binwalk2(input_file)
     Repeat()
def print_subchoices1():
    print(Fore.BLUE)
    print("Select Options to perform Operations:")
    print("                 1)  single_squashfs")
    print("                 2)  Multiple_squashfs")
    subchoices1 = int(input("select option from given menu :"))
    time.sleep(0.8)
    if subchoices1 == 1:
     fmk(input_file)
     Repeat()
    if subchoices1 == 2:
     fmk1(input_file)
     #function2()
     Repeat()
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
        print("------------")
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error running binwalk command:", e)
def run_binwalk2(input_file):
    try:
        print(Fore.RED)
        output = subprocess.check_output(["binwalk", "-e", input_file], universal_newlines=True)
        print("***********")
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error running binwalk command:", e)
def run_binwalk3(input_file):
    try:
        print(Fore.RED)
        output = subprocess.check_output(["binwalk", "-Y", input_file], universal_newlines=True)
        print("__________")
        print(output)
    except subprocess.CalledProcessError as e:
        print("Error running binwalk command:", e)
#------------------------------------------------------------------------------------------------------------#
def run_radare2(input_file):
    current_datetime =datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    str_current_datetime = str(current_datetime)
    output_file1 = "/home/pranav/fev-bin-hammer/Assembly_"+str_current_datetime+".txt"
    try:
        print(Fore.RED)
   # radare2 -a x86 -b elf -qc "pd 50 > disassembly.txt; e scr.interactive=true;V" /home/pranav/Downloads/APT_IVN.elf
       # command = ["radare2", "-a","x86","-b","elf","-qc","pd 50 > disassembly.txt510;",input_file]
        command = ["r2", "-AA", "-qc", f"e asm.arch=arm; e asm.bits=32; aaa; pd 3000 > {output_file1}", input_file]
       # command = ["radare2", "-a","x86","-b","elf","-qc","pd 50 > disassembly.txt510;",input_file]
        subprocess.run(command, check=True)
        strings_output = subprocess.check_output(["strings", input_file], universal_newlines=True)
        res = strings_output.split()
        lst = [x.lower() for x in res]
        lst1 = [x.lower() for x in crypto_keywords]
                 # print(res)
        with open(output_file1, "w") as f:
            f.write(output_file1)
        a_set = set(lst)
        b_set = set(lst1)

        if (a_set & b_set):
            print(a_set & b_set)
        else:
            print("No common elements") 
        print(f"Assembly code saved to '{output_file1}'.")
    except subprocess.CalledProcessError as e:
        print("Error running Radare2 command:", e)
    try:
        #print(Fore.RED)
   # radare2 -a x86 -b elf -qc "pd 50 > disassembly.txt; e scr.interactive=true;V" /home/pranav/Downloads/APT_IVN.elf
        command = ["radare2", "-a","x86","-b","elf","-qc","pd 50 > disassembly.txt; e scr.interactive=true;V",input_file]
       # command = ["r2", "-AA", "-qc", f"e asm.arch=arm; e asm.bits=32; aaa; pd 3000 > {output_file1}", input_file]
        subprocess.run(command, check=True)
       # print(f"Assembly code saved to '{output_file}'.")
    except subprocess.CalledProcessError as e:
        print("Error running Radare2 command:", e)

crypto_keywords = ["crypt", "encrypt","ENCRYPTION", "decrypt", "cipher", "hash", "key","ssid","signature","UUID", "digest", "block", "stream", "symmetric", "asymmetric", "RSA", "AES", "DES", "MD5", "SHA", "ECDSA", "Diffie-Hellman", "Elliptic_Curve", "PKCS", "PGP", "SSL", "TLS", "X.509", "HMAC", "CBC", "ECB", "CTR", "GCM", "RC4", "Blowfish", "Twofish", "Salsa", "ChaCha", "PBKDF", "KDF", "PRNG", "Random", "Entropy", "crypt", "encrypt", "decrypt", "hash", "cipher", "AES", "SHA", "HSM", "base_64"]

def extract_strings(input_file):
    try:
         print(Fore.RED)
         current_datetime =datetime.now().strftime("%Y-%m-%d %H-%M-%S")
         str_current_datetime = str(current_datetime)
         output_file = "/home/pranav/fev-bin-hammer/readbinarystings_"+str_current_datetime+".txt"
         strings_output = subprocess.check_output(["strings", input_file], universal_newlines=True)
         res = strings_output.split()
         lst = [x.lower() for x in res]
         lst1 = [x.lower() for x in crypto_keywords]
                 # print(res)
         with open(output_file, "w") as f:
            f.write(output_file)
         a_set = set(lst)
         b_set = set(lst1)

         if (a_set & b_set):
            print(a_set & b_set)
         else:
            print("No common elements") 
         print(f"Printable strings extracted from '{input_file}' and saved to '{output_file}'.")
    except subprocess.CalledProcessError as e:
        print("Error running strings command:", e)
def analyze_crypto(input_file):
    #r2 = None
    try:
        print(Fore.RED)
        # Add Radare2Decompile and report generation with cve_scanning directory to PATH
        radare2_path = "/home/pranav/radare2"  # Replace with the actual path to Radare2
        os.environ["PATH"] += os.pathsep + radare2_path

        # Open the binary in Radare2
        r2 = r2pipe.open(input_file)
        r2.cmd("aaa")

        # List all functions in the binary
        functions = r2.cmdj("aflj")
        res = functions.split()
        lst = [x.lower() for x in res]
        lst1 = [x.lower() for x in crypto_keywords]
                 # print(res)
        with open(output_file, "w") as f:
            f.write(functions)
        c_set = set(lst)
        d_set = set(lst1)

        if (c_set & d_set):
            print(c_set & d_set)
        else:
            print("No common elements") 
        # Initialize a list to store cryptographic functions
        crypto_functions = []
        # Keywords indicating cryptographic operations
        crypto_keywords = ["crypt", "encrypt", "decrypt", "cipher", "hash", "key","ssid","signature", "digest", "block", "stream", "symmetric", "asymmetric", "RSA", "AES", "DES", "MD5", "SHA", "ECDSA", "Diffie-Hellman", "Elliptic_Curve", "PKCS", "PGP", "SSL", "TLS", "X.509", "HMAC", "CBC", "ECB", "CTR", "GCM", "RC4", "Blowfish", "Twofish", "Salsa", "ChaCha", "PBKDF", "KDF", "PRNG", "Random", "Entropy", "crypt", "encrypt", "decrypt", "hash", "cipher", "AES", "SHA", "HSM", "base_64"]
        # Iterate through each function to identify cryptographic functions
        for func in functions:
            for keyword in crypto_keywords:
                if keyword in func["name"].lower():
                    crypto_functions.append(func)
                    break  # Move to the next function once a keyword is found

        # Print the identified cryptographic functions
        if crypto_functions:
            print("Cryptographic functions:")
            for func in crypto_functions:
                print("- Function: {} (Address: {})".format(func["name"], func["offset"]))
        else:
            print("No cryptographic functions found.")
    except FileNotFoundError:
        print("ERROR: Cannot find radare2 in PATH")
    finally:
        # Close Radare2 if it was opened successfully
        if r2 is not None:
            r2.quit()
def generate_radare2_command(architecture, file_format, family, input_file):
     #generate_radare2_command(architecture, file_format, family, input_file)
    current_datetime =datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    str_current_datetime = str(current_datetime)
    output_file1 = "/home/pranav/fev-bin-hammer/Assembly_"+str_current_datetime+".txt"
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

    if not architecture or not file_format or not family or not input_file:
        raise ValueError("Architecture, file format, family, and input file must be provided.")
    # Validate architecture
    if architecture.lower()or architecture.upper()in SUPPORTED_ARCHITECTURES:
       # raise ValueError(f"Unsupported architecture: {architecture}")
    # Create the command with user-specified architecture, file format, and family
      command = ["radare2", "-a", architecture, "-b", file_format, "-e", f"asm.arch={family}", "-qc", "pdga 100 > disassembly.txt; e scr.interactive=true;V", input_file]
      return command
      print  (command)
    else:
        raise ValueError(f"Unsupported architecture: {architecture}")
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
def arch_details(input_file):
   try:
      print(Fore.RED)
      command =["rabin2","-I",input_file]
      subprocess.run(command, check=True)
      #sys.exit(1)
      #print(command)
   except subprocess.CalledProcessError as e:
        print("Error running arch command:", e)
def run_arch_detect(input_file):
    try:
        print(Fore.RED)
        # Command to run Radare2 with the specified file and save assembly code to a file
        command = ["r2", "-A", "-qc", f"e asm.arch=arm; e asm.bits=32; aaa; pd 3000", input_file]
        subprocess.run(command, check=True)

    except subprocess.CalledProcessError as e:
        print("Error running Radare2 command:", e)
def cve_checker(log_file):
     f= open(log_file,mode="rb")
     data=f.read
     print(data)
def fmk(input_file):
    os.chdir(r"/home/pranav/fev-bin-hammer/firmware-mod-kit") 
    try:
        print(Fore.RED)
        command = ["./extract-firmware.sh",input_file]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running Radare2 command:", e)
def fmk1(input_file):
    os.chdir(r"/home/pranav/fev-bin-hammer/firmware-mod-kit") 
    try:
        print(Fore.RED)
        command = ["./extract-multisquashfs-firmware.sh",input_file]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running Radare2 command:", e)
def firmware_repack(input_directory):
    os.chdir(r"/home/pranav/fev-bin-hammer/firmware-mod-kit") 
    try:
        print(Fore.RED)
        #os.chdir(r"/home/firmware-mod1-kit")
        command = ["./build-firmware.sh",input_directory]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running Radare2 command:", e)

def print_banner():
    banner = """
███████╗███████╗██╗   ██╗      ██████╗ ██╗███╗   ██╗        ██╗  ██╗ █████╗ ███╗   ███╗███╗   ███╗███████╗██████╗ 
██╔════╝██╔════╝██║   ██║      ██╔══██╗██║████╗  ██║        ██║  ██║██╔══██╗████╗ ████║████╗ ████║██╔════╝██╔══██╗
█████╗  █████╗  ██║   ██║█████╗██████╔╝██║██╔██╗ ██║███████╗███████║███████║██╔████╔██║██╔████╔██║█████╗  ██████╔╝
██╔══╝  ██╔══╝  ╚██╗ ██╔╝╚════╝██╔══██╗██║██║╚██╗██║ ══════ ██╔══██║██╔══██║██║╚██╔╝██║██║╚██╔╝██║██╔══╝  ██╔══██╗
██║     ███████╗ ╚████╔╝       ██████╔╝██║██║ ╚████║       ╗██║  ██║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║███████╗██║  ██║
╚═╝     ╚══════╝  ╚═══╝        ╚═════╝ ╚═╝╚═╝  ╚═══╝        ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝                                                                            
    """
    print(Fore.GREEN + banner)
# s in the firmware stands for security
def detect_cryptographic_operations(file):
    with open(file, "rb") as f:
    #with open(,"file_namerb") as f:
        binary_data = f.read()

    aes_detected = True
    des_detected = True
    sha1_detected = True
    sha256_detected = True
    md5_detected = True

    if b'AES' in binary_data:
        aes_detected = True
    if b'DES' in binary_data:
        des_detected = True
    if b'SHA1' in binary_data:
        sha1_detected = True
    if b'SHA256' in binary_data:
        sha256_detected = True
    if b'MD5' in binary_data:
        md5_detected = True
    try:
        cipher = Cipher(algorithms.AES(b'0' * 16), modes.ECB())
        aes_detected = False
    except Exception:
        pass
    try:
        cipher = Cipher(algorithms.TripleDES(b'0' * 24), modes.ECB())
        des_detected = False
    except Exception:
        pass
    try:
        sha1_hash = hashlib.sha1(b'').hexdigest()
        sha1_detected = False
    except Exception:
        pass
    try:
        sha256_hash = hashlib.sha256(b'').hexdigest()
        sha256_detected = False
    except Exception:
        pass
    try:
        md5_hash = hashlib.md5(b'').hexdigest()
        md5_detected = False
    except Exception:
        pass
    if aes_detected:
        print("AES encryption or decryption operation detected.")
    if des_detected:
        print("DES encryption or decryption operation detected.")
    if sha1_detected:
        print("SHA-1 hashing operation detected.")
    if sha256_detected:
        print("SHA-256 hashing operation detected.")
    if md5_detected:
        print("MD5 hashing operation detected.")
    if not (aes_detected or des_detected or sha1_detected or sha256_detected or md5_detected):
        print("No cryptographic operations detected.")
#def fermadyne

if __name__ == "__main__":
   # print("ji")
    print_banner()
   # playsound('/home/pranav/Downloads/mixkit-8-bit-bomb-explosion-2811.wav')
    #print('playing sound using  playsound')
def Repeat():
    print("--------------------------------------------------------------------------------------------------------------------------------------------------------")
    print_choices()
    file_extension = os.path.splitext(input_file)
    choices = int(input("select option from given menu :"))
    #choices2 = chr(input("More details about tool :"))
    if choices == 1:
     function1()
     time.sleep(2)
     Repeat()
    if choices == 2:
     function2()
     time.sleep(2)
     Repeat()
    if choices == 3:
     function3()
     time.sleep(2)
     Repeat()
 #   time.sleep(1)
    if choices == 4:
     function4()
     time.sleep(2)
     Repeat()
#    time.sleep(1)
    if choices == 5:
     function5()
     time.sleep(2)
     Repeat()
    if choices == 6:
     function6()
     time.sleep(2)
     Repeat()
    if choices == 7:
     function7()
     time.sleep(2)
     Repeat()
    if choices == 8:
     function8()
     time.sleep(2)
     Repeat()
    if choices == 9:
     function9()
     time.sleep(2)
     Repeat()
    if choices == 10:
     function10()
     time.sleep(2)
     Repeat()
    if choices == 11:
     function11()
     time.sleep(2)
     Repeat()
    if choices == 12:
     function12()
     time.sleep(2)
     Repeat()
    if choices == 13:
     function13()
     time.sleep(2)
   #  time.sleep(2)
     Repeat()
    if choices == 14:
     function14()
     time.sleep(2)
     Repeat()
    print(type(choices))
    if choices >=15 & choices<1:
     print("invalid_selection")
     Repeat()
    time.sleep(0.3)
input_file = click.prompt("Enter the path of the file")
current_datetime =datetime.now().strftime("%Y-%m-%d %H-%M")
str_current_datetime = str(current_datetime)
check_file = os.path.isfile(input_file)
if( check_file == False):
        print("file not found")
        input_file = click.prompt("Enter the path of the file:")
        str_current_datetime = str(current_datetime)
        check_file = os.path.isfile(input_file)
        if( check_file == False):
         print("file not found")
         input_file = click.prompt("Enter the path of the file")
else:
    #print(".........")
    time.sleep(0.5)
while(1):
    print_choices()
    file_extension = os.path.splitext(input_file)
    choices = int(input("select option from given menu: "))
    #time.sleep(0.5)
    if choices == 1:
     function1()
     time.sleep(2)
     Repeat()
    if choices == 2:
     function2()
     time.sleep(2)
     Repeat()
    if choices == 3:
     function3()
     time.sleep(2)
     Repeat()
    time.sleep(1)
    if choices == 4:
     function4()
     time.sleep(2)
     Repeat()
 #   time.sleep(1)
    if choices == 5:
     function5()
     time.sleep(2)
     Repeat()
    if choices == 6:
      function6()
      time.sleep(2)
      Repeat()
    if choices == 7:
     function7()
     time.sleep(2)
     Repeat()
    if choices == 8:
     function8()
     time.sleep(2)
     Repeat()
    if choices == 9:
     function9()
     time.sleep(2)
     Repeat()
    if choices == 10:
     function10()
     time.sleep(2)
     Repeat()
    if choices == 11:
     function11()
     time.sleep(2)
     Repeat()
    if choices == 12:
     function12()
     time.sleep(2)
     Repeat()
    if choices == 13:
     function13()
     time.sleep(2)
     Repeat()
    if choices == 14:
     function14()
     time.sleep(2)
     Repeat()
    print(type(choices))
    if choices >=15 & choices<1:
     print("invalid_selection")
     Repeat()
    print(type(choices))