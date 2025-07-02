
A Python script that scans binary files for unsafe functions that could lead to memory corruption vulnerabilities like buffer overflows.

- Uses `nm` to extract symbols from binary files (ELF, PE, Mach-O)
- Detects unsafe functions that can cause security issues

## Default scan (high-risk functions)

By default, BinScan looks for the most dangerous functions:
- `strcpy`, `strcat`, `strncpy`, `strncat`
- `strtok`, `strtok_r`, `sprintf`, `vsprintf`, `gets`

## Installation

Install binutils first:
```bash
# Ubuntu/Debian
sudo apt-get install binutils

# CentOS/RHEL
sudo yum install binutils

# macOS
brew install binutils
```

Then install Python dependencies:
```bash
pip3 install colorama
```

## Usage

Scan a single file:
```bash
python3 BinScan.py --file /path/to/binary.so
```

Scan a directory:
```bash
python3 BinScan.py --dir /path/to/binaries/
```

Scan for all unsafe functions (not just high-risk):
```bash
python3 BinScan.py --file /path/to/binary.so --all
```

## Output

The script shows which libraries contain unsafe functions and lists them. During scanning it only shows "Analyzing: filename" and provides a summary at the end.

## Limitations

- Requires binary files to have symbols (not stripped)
- Static analysis only
