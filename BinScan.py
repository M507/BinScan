#!/usr/bin/env python3
"""
Binary Vulnerability Scanner
Scans binary files in a directory for unsafe functions that could lead to memory corruption vulnerabilities.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
from collections import defaultdict
import re
from typing import Dict, List, Set, Tuple
import colorama
from colorama import Fore, Back, Style

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class VulnerabilityScanner:
    """Scanner for unsafe functions in binary files."""
    
    # Default high-risk unsafe functions (most dangerous)
    DEFAULT_UNSAFE_FUNCTIONS = {
        'strcpy', 'strcat', 'strncpy', 'strncat', 'strtok', 'strtok_r',
        'sprintf', 'vsprintf', 'gets'
    }
    
    # All unsafe functions that could lead to memory corruption vulnerabilities
    ALL_UNSAFE_FUNCTIONS = {
        # Buffer overflow prone functions
        'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'scanf', 'fscanf',
        'sscanf', 'printf', 'fprintf', 'snprintf', 'vsnprintf', 'strncpy',
        'strncat', 'memcpy', 'memmove', 'memset', 'bcopy', 'bcmp', 'bzero',
        
        # Memory allocation without bounds checking
        'malloc', 'calloc', 'realloc', 'free', 'alloca',
        
        # String manipulation without bounds checking
        'strlen', 'strcmp', 'strncmp', 'strcasecmp', 'strncasecmp',
        'strchr', 'strrchr', 'strstr', 'strtok', 'strtok_r',
        
        # File operations that could be exploited
        'fopen', 'fclose', 'fread', 'fwrite', 'fgets', 'fputs',
        'read', 'write', 'open', 'close', 'creat',
        
        # Network functions that could be exploited
        'recv', 'send', 'recvfrom', 'sendto', 'accept', 'connect',
        'bind', 'listen', 'socket', 'select', 'poll',
        
        # System calls that could be dangerous
        'system', 'popen', 'exec', 'execl', 'execlp', 'execle', 'execv',
        'execvp', 'execvpe', 'fork', 'vfork', 'clone',
        
        # Signal handling
        'signal', 'sigaction', 'sigprocmask', 'sigpending', 'sigsuspend',
        
        # Environment and process
        'setenv', 'unsetenv', 'putenv', 'getenv', 'clearenv',
        'setuid', 'setgid', 'seteuid', 'setegid', 'setreuid', 'setregid',
        
        # Time functions that could be exploited
        'time', 'ctime', 'localtime', 'gmtime', 'strftime', 'strptime',
        
        # Random number generation (if not properly seeded)
        'rand', 'random', 'srand', 'srandom',
        
        # Mathematical functions that could cause issues
        'pow', 'sqrt', 'log', 'exp', 'sin', 'cos', 'tan',
        
        # Additional dangerous functions
        'scanf', 'fscanf', 'sscanf', 'vscanf', 'vfscanf', 'vsscanf',
        'tmpnam', 'tempnam', 'mktemp', 'mkstemp', 'mkdtemp',
        'chmod', 'chown', 'umask', 'access', 'stat', 'lstat', 'fstat',
        'link', 'symlink', 'unlink', 'rename', 'remove', 'mkdir', 'rmdir',
        'chdir', 'getcwd', 'realpath', 'canonicalize_file_name'
    }
    
    def __init__(self, target_path: str, scan_all: bool = False):
        """Initialize the scanner with a file or directory path."""
        self.target_path = Path(target_path)
        self.scan_all = scan_all
        # Use all functions if --all flag is set, otherwise use default high-risk functions
        self.UNSAFE_FUNCTIONS = self.ALL_UNSAFE_FUNCTIONS if scan_all else self.DEFAULT_UNSAFE_FUNCTIONS
        self.results = defaultdict(list)
        self.total_files = 0
        self.files_with_symbols = 0
        self.total_unsafe_functions = 0
        
    def is_binary_file(self, file_path: Path) -> bool:
        """Check if a file is a binary file."""
        try:
            # Check file magic numbers for common binary formats
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                
            # ELF files
            if magic.startswith(b'\x7fELF'):
                return True
            # PE files (Windows executables)
            elif magic.startswith(b'MZ'):
                return True
            # Mach-O files (macOS)
            elif magic.startswith(b'\xfe\xed\xfa\xce') or magic.startswith(b'\xce\xfa\xed\xfe'):
                return True
            # Universal binary (macOS)
            elif magic.startswith(b'\xca\xfe\xba\xbe'):
                return True
                
        except (IOError, OSError):
            pass
            
        return False
    
    def get_symbols_from_binary(self, file_path: Path) -> List[str]:
        """Extract symbols from a binary file using nm."""
        symbols = []
        
        try:
            # Get regular symbols
            result = subprocess.run(
                ['nm', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        # Parse nm output: <address> <type> <name>
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            symbol_type = parts[1]
                            symbol_name = parts[2]
                            # Only include function symbols (t, T, w, W)
                            if symbol_type in ['t', 'T', 'w', 'W']:
                                symbols.append(symbol_name)
            
            # Get dynamic symbols (imported functions)
            result_dyn = subprocess.run(
                ['nm', '-D', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result_dyn.returncode == 0:
                for line in result_dyn.stdout.split('\n'):
                    if line.strip():
                        # Parse nm output: <address> <type> <name>
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            symbol_type = parts[1]
                            symbol_name = parts[2]
                            # Only include function symbols (U, T, W)
                            if symbol_type in ['U', 'T', 'W']:
                                # Clean up symbol name (remove @LIBC, etc.)
                                if '@' in symbol_name:
                                    symbol_name = symbol_name.split('@')[0]
                                symbols.append(symbol_name)
                        elif len(parts) == 2 and parts[0] == 'U':
                            # Handle undefined symbols format: U <name>
                            symbol_name = parts[1]
                            if '@' in symbol_name:
                                symbol_name = symbol_name.split('@')[0]
                            symbols.append(symbol_name)
            
            return symbols
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}Warning: nm timeout for {file_path}")
            return []
        except FileNotFoundError:
            print(f"{Fore.RED}Error: nm not found. Please install binutils.")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Error processing {file_path}: {e}")
            return []
    
    def find_unsafe_functions(self, symbols: List[str]) -> List[str]:
        """Find unsafe functions in the symbol list."""
        unsafe_found = []
        for symbol in symbols:
            # Check if symbol contains any unsafe function name
            for unsafe_func in self.UNSAFE_FUNCTIONS:
                # Match exact function name or function name as part of larger name
                if (symbol == unsafe_func or 
                    symbol.endswith(f'_{unsafe_func}') or 
                    symbol.endswith(f'{unsafe_func}_') or
                    f'_{unsafe_func}_' in symbol or
                    symbol.startswith(f'{unsafe_func}_') or
                    symbol.lower() == unsafe_func.lower() or
                    unsafe_func in symbol.lower()):
                    unsafe_found.append(unsafe_func)
                    break
        return unsafe_found
    
    def scan_file(self, file_path: Path) -> None:
        """Scan a single binary file."""
        if not file_path.exists():
            print(f"{Fore.RED}Error: File '{file_path}' does not exist.")
            return
            
        if not file_path.is_file():
            print(f"{Fore.RED}Error: '{file_path}' is not a file.")
            return
            
        if not self.is_binary_file(file_path):
            print(f"{Fore.YELLOW}Skipping {file_path.name} (not a binary file)")
            return
            
        self.total_files += 1
        print(f"{Fore.WHITE}Analyzing: {file_path.name}")
        
        symbols = self.get_symbols_from_binary(file_path)
        if symbols:
            self.files_with_symbols += 1
            unsafe_functions = self.find_unsafe_functions(symbols)
            
            if unsafe_functions:
                self.results[str(file_path)] = unsafe_functions
                self.total_unsafe_functions += len(unsafe_functions)
        else:
            print(f"  {Fore.YELLOW}No symbols found or not a valid binary")
    
    def scan_directory(self) -> None:
        """Scan the directory for binary files and analyze them."""
        if not self.target_path.exists():
            print(f"{Fore.RED}Error: Path '{self.target_path}' does not exist.")
            sys.exit(1)
            
        if self.target_path.is_file():
            # If it's a file, scan just that file
            self.scan_file(self.target_path)
        elif self.target_path.is_dir():
            # If it's a directory, scan all files recursively
            print(f"{Fore.CYAN}Scanning directory: {self.target_path}")
            print(f"{Fore.CYAN}Looking for unsafe functions that could cause memory corruption...")
            print("-" * 80)
            
            # Find all files in the directory
            for file_path in self.target_path.rglob('*'):
                if file_path.is_file():
                    self.scan_file(file_path)
        else:
            print(f"{Fore.RED}Error: '{self.target_path}' is not a valid file or directory.")
            sys.exit(1)
    
    def print_results(self) -> None:
        """Print the scan results: only show vulnerable library names, their path, number of unsafe functions, and list all unsafe function names in one line."""
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}{Style.BRIGHT}VULNERABLE LIBRARIES SUMMARY")
        print("=" * 80)

        if not self.results:
            print(f"\n{Fore.GREEN}{Style.BRIGHT}No unsafe functions found! 🎉")
            return

        for file_path, unsafe_funcs in self.results.items():
            file_name = Path(file_path).name
            unique_funcs = sorted(set(unsafe_funcs))
            print(f"\n{Fore.RED}{Style.BRIGHT}Library: {file_name}")
            print(f"{Fore.WHITE}Path: {file_path}")
            print(f"{Fore.YELLOW}Number of unique unsafe functions found: {len(unique_funcs)}")
            print(f"{Fore.RED}Unsafe functions: {', '.join(unique_funcs)}")

def main():
    """Main function to run the vulnerability scanner."""
    script_name = Path(__file__).name
    parser = argparse.ArgumentParser(
        description="Scan binary files for unsafe functions that could cause memory corruption vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python3 {script_name} --file /path/to/binary/file.so
  python3 {script_name} --dir /path/to/binaries/
  python3 {script_name} --file /path/to/binary/file.so --all
  python3 {script_name} --dir /path/to/binaries/ --all
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', type=str, help='Path to a single binary file to scan')
    group.add_argument('--dir', type=str, help='Path to a directory containing binary files to scan')

    parser.add_argument('--all', action='store_true', 
                       help='Scan for all unsafe functions (default: only high-risk functions)')

    parser.add_argument(
        '--version',
        action='version',
        version='BinScan v1.0'
    )

    args = parser.parse_args()

    # Check if nm is available
    try:
        subprocess.run(['nm', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Fore.RED}Error: nm not found. Please install binutils:")
        print(f"{Fore.WHITE}  Ubuntu/Debian: sudo apt-get install binutils")
        print(f"{Fore.WHITE}  CentOS/RHEL: sudo yum install binutils")
        print(f"{Fore.WHITE}  macOS: brew install binutils")
        sys.exit(1)

    # Determine target path
    if args.file:
        target = args.file
    elif args.dir:
        target = args.dir
    else:
        parser.error('You must specify either --file or --dir')

    # Create and run scanner
    scanner = VulnerabilityScanner(target, args.all)
    scanner.scan_directory()
    scanner.print_results()

if __name__ == "__main__":
    main() 
