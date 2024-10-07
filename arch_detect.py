import subprocess
import click
import json

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return None
    except Exception as e:
        return str(e)

def detect_architecture(file_path):
    results = {}

    # Using file command
    file_output = run_command(f'file {file_path}')
    if file_output:
        results['file'] = file_output

    # Using r2 command
    r2_output = run_command(f'r2 -c "iI~arch" -qq {file_path}')
    if r2_output:
        results['r2'] = r2_output

    # Using rabin2
    rabin2_output = run_command(f'rabin2 -I {file_path}')
    if rabin2_output:
        results['rabin2'] = rabin2_output

    return results

def parse_results(results):
    architecture_info = {}

    # Parsing file command output
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

    # Parsing r2 command output
    if 'r2' in results:
        r2_output = results['r2']
        if 'arch' in r2_output:
            architecture_info['architecture'] = r2_output.split(':')[1].strip()
        else:
            architecture_info['architecture'] = 'arch not found'

    # Parsing rabin2 output
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

# Main script execution
if __name__ == "__main__":
    file_path = click.prompt("Enter the path of the file", type=str)
    results = detect_architecture(file_path)
    arch_info = parse_results(results)

    # Print parsed architecture information
    print(json.dumps(arch_info, indent=4))
