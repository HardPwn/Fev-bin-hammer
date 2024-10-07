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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
file = "/home/pranav/fev-bin-hammer/test_binaries/APT_IVN.elf"
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
        cipher = Cipher(algorithms.AES(b'0' * 32), modes.ECB())
        aes_detected = True
    except Exception:
        pass
    try:
        cipher = Cipher(algorithms.TripleDES(b'0' * 32), modes.ECB())
        des_detected = True
    except Exception:
        pass
    try:
        sha1_hash = hashlib.sha1(b'').hexdigest()
        sha1_detected = True
    except Exception:
        pass
    try:
        sha256_hash = hashlib.sha256(b'').hexdigest()
        sha256_detected = True
    except Exception:
        pass
    try:
        md5_hash = hashlib.md5(b'').hexdigest()
        md5_detected = True
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

detect_cryptographic_operations(file)