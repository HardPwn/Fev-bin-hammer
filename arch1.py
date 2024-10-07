import os
import r2pipe
from colorama import Fore, init

def suppress_output(func):
    """Decorator to suppress stdout and stderr output of a function."""
    def wrapper(*args, **kwargs):
        with open(os.devnull, 'w') as devnull:
            old_stdout = os.dup(1)
            old_stderr = os.dup(2)
            os.dup2(devnull.fileno(), 1)
            os.dup2(devnull.fileno(), 2)
            try:
                return func(*args, **kwargs)
            finally:
                os.dup2(old_stdout, 1)
                os.dup2(old_stderr, 2)
                os.close(old_stdout)
                os.close(old_stderr)
    return wrapper

@suppress_output
def analyze_binary(r2):
    r2.cmd("aaa")

def decompile_interactive(input_file):
    try:
        # Initialize colorama
        init(autoreset=True)

        # Open the binary in Radare2
        r2 = r2pipe.open(input_file)

        # Apply relocations
        r2.cmd("e bin.relocs.apply=true")
        # Analyze the binary
        analyze_binary(r2)

        print(Fore.GREEN + "Interactive Decompiler. Type 'help' for commands, 'quit' to exit.")

        while True:
            command = input(Fore.BLUE + "r2> ").strip()

            if command == "quit":
                break
            elif command == "help":
                print(Fore.YELLOW + """
Available commands:
- quit: Exit the decompiler
- aflj: List all functions in the binary
- pd @ <address>: Disassemble at a specific address
- pdd @ <address>: Decompile at a specific address
- af: Analyze functions
- any valid r2 command
                """)
            elif command.startswith("pdd @"):
                address = command.split('@')[-1].strip()
                output = r2.cmd(f"pdd @{address}")
                print(output)
            else:
                output = r2.cmd(command)
                print(output)

    except FileNotFoundError:
        print(Fore.RED + "ERROR: Cannot find radare2 in PATH")
    except Exception as e:
        print(Fore.RED + f"ERROR: {str(e)}")
    finally:
        # Close Radare2 if it was opened successfully
        if r2 is not None:
            r2.quit()

# Example usage:
# decompile_interactive("/path/to/binary")
