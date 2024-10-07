
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
from colorama import Fore, init
# for playing note.mp3 file

#from Crypto.Cipher import AES, DES
#from Crypto.Hash import SHA1, SHA256, MD5
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def file_extension_to_input_format(file_extension):
    # Placeholder function, you need to implement this based on your requirements
    return file_extension

def run_emba(input_file, output_file, your_username):
    input_file = os.path.expanduser(input_file)
    output_file = os.path.expanduser(output_file)
    os.chdir(r"/home/pranav/Fev-Bin-Hammer-Distributable/emba")
    print("hi")
    parts = input_file.split(os.sep)
    home_index = parts.index(your_username)
    relative_path = "../" + os.sep + os.sep.join(parts[home_index+1:])
    print(relative_path)

    try:
        log_dir = os.path.join(os.path.dirname(output_file), "logs")
        os.makedirs(log_dir, exist_ok=True)
        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M")
        log_file = os.path.join(log_dir, "emba_log_" + current_datetime + ".txt")
        
        command = ["sudo", "./emba", "-l", log_file, "-f", relative_path, "-p", "./scan-profiles/default-scan.emba"]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running emba command:", e)

def cve_checker(cve_file):
    print(Fore.RED)
    with open(cve_file) as f:
        data = f.read()
        print(data)

# Example usage
input_file = "fev-bin-hammer/test_binaries/btms_Changed.bin"
output_file = "~/Downloads/ji.txt"
your_username = "pranav"  # Replace with your actual username

run_emba(input_file, output_file, your_username)

cve_file = "/home/pranav/Downloads/logs/emba_log.txt"
cve_checker(cve_file)
