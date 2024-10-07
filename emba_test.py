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
#from pyhidra import HidraController
#from pyhidra.util import DecompilationOptionsoutput_directory = "/home/pranav/emba_logs"
input_file1 = "~/Downloads/application.hex"
your_username="pranav"
def run_emba(input_file, output_file,your_username):
    input_file = os.path.expanduser(input_file)
    output_file = os.path.expanduser(output_file)A
    os.chdir(r"/home/pranav/Fev-Bin-Hammer-Distributable/emba")
    output_file = os.path.expanduser(output_file)
    parts = input_file.split(os.sep)
    home_index = parts.index("your_username")
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
 
# Example usage:
input_file = "/home/your_username/Downloads/application.hex"
output_file = "~/Downloads/ji.txt"
log_dir = os.path.join(os.path.dirname(output_file), "logs")
log_file = os.path.join(log_dir, "emba_log.txt")
run_emba(input_file, output_file,your_username)
print("---------------------------cve_checker-----------------------------------------")
cve_file = "/home/pranav/Downloads/logs/emba_log.txt/s17_cwe_checker.txt"
def cve_checker(cve_file):
    with open(cve_file) as f:
        data = f.read()
        print(data)
cve_checker(cve_file)