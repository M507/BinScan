#!/usr/bin/env python3
"""
# python3 checksec_reporting.py --dir ./arm64-v8a --checksec /root/BinScan/checksec
Checksec Reporting Script
Scans binary files in a directory using checksec and reports files with specific security properties.
"""

import os
import sys
import subprocess
import argparse
import json
from pathlib import Path
from typing import Dict, List
import colorama
from colorama import Fore, Style

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class ChecksecReporter:
    """Reporter for checksec security properties."""
    
    def __init__(self, checksec_path: str = "./checksec"):
        """Initialize the reporter with checksec path."""
        self.checksec_path = Path(checksec_path)
        self.results = {
            'no_canary': [],
            'no_fortify': [],
            'no_relro': [],
            'has_symbols': []
        }
    
    def run_checksec(self, directory: str) -> Dict:
        """Run checksec on the given directory and return JSON output."""
        if not self.checksec_path.exists():
            print(f"{Fore.RED}Error: checksec not found at {self.checksec_path}")
            print(f"{Fore.WHITE}Please ensure checksec is in the current directory or provide the correct path.")
            sys.exit(1)
        
        # Make checksec executable if it isn't already
        if not os.access(self.checksec_path, os.X_OK):
            try:
                os.chmod(self.checksec_path, 0o755)
            except OSError as e:
                print(f"{Fore.YELLOW}Warning: Could not make checksec executable: {e}")
        
        # Run checksec command
        cmd = [str(self.checksec_path), f"--dir={directory}", "--output=json"]
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                print(f"{Fore.RED}Error: checksec failed with return code {result.returncode}")
                if result.stderr:
                    print(f"{Fore.YELLOW}Error output: {result.stderr}")
                sys.exit(1)
            
            # Parse JSON output
            try:
                data = json.loads(result.stdout)
                return data
            except json.JSONDecodeError as e:
                print(f"{Fore.RED}Error: Failed to parse checksec JSON output: {e}")
                print(f"{Fore.YELLOW}Raw output: {result.stdout[:500]}...")
                sys.exit(1)
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}Error: checksec command timed out")
            sys.exit(1)
        except FileNotFoundError:
            print(f"{Fore.RED}Error: checksec not found. Please ensure it's in the current directory.")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}Error: Failed to run checksec: {e}")
            sys.exit(1)
    
    def analyze_results(self, data: Dict) -> None:
        """Analyze checksec results and categorize files by security properties."""
        # The JSON structure from checksec may vary, but typically it's a dict
        # where keys are file paths and values are security properties
        
        # Handle different possible JSON structures
        files_data = {}
        
        if isinstance(data, dict):
            # Check if it's a nested structure or flat
            if 'files' in data:
                files_data = data['files']
            elif any(isinstance(v, dict) for v in data.values()):
                files_data = data
            else:
                # Might be a single file result
                files_data = data
        
        for file_path, properties in files_data.items():
            if not isinstance(properties, dict):
                continue
            
            # Normalize property names (checksec may use different case/format)
            props_lower = {k.lower(): v for k, v in properties.items()}
            
            # Check for canary = "no"
            canary = props_lower.get('canary', '').lower()
            if canary == 'no':
                self.results['no_canary'].append(file_path)
            
            # Check for FORTIFY = "no"
            fortify = props_lower.get('fortify', '').lower()
            if fortify == 'no':
                self.results['no_fortify'].append(file_path)
            
            # Check for RELRO = "no"
            relro = props_lower.get('relro', '').lower()
            if relro == 'no':
                self.results['no_relro'].append(file_path)
            
            # Check for Symbols = "yes"
            symbols = props_lower.get('symbols', '').lower()
            if symbols == 'yes':
                self.results['has_symbols'].append(file_path)
    
    def print_results(self) -> None:
        """Print the categorized results."""
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}{Style.BRIGHT}CHECKSEC SECURITY REPORT")
        print("=" * 80)
        
        # Files with no canary
        print(f"\n{Fore.RED}{Style.BRIGHT}Files with Canary = NO ({len(self.results['no_canary'])}):")
        print("-" * 80)
        if self.results['no_canary']:
            for file_path in sorted(self.results['no_canary']):
                print(f"  {Fore.WHITE}{file_path}")
        else:
            print(f"  {Fore.GREEN}None found")
        
        # Files with no FORTIFY
        print(f"\n{Fore.RED}{Style.BRIGHT}Files with FORTIFY = NO ({len(self.results['no_fortify'])}):")
        print("-" * 80)
        if self.results['no_fortify']:
            for file_path in sorted(self.results['no_fortify']):
                print(f"  {Fore.WHITE}{file_path}")
        else:
            print(f"  {Fore.GREEN}None found")
        
        # Files with no RELRO
        print(f"\n{Fore.RED}{Style.BRIGHT}Files with RELRO = NO ({len(self.results['no_relro'])}):")
        print("-" * 80)
        if self.results['no_relro']:
            for file_path in sorted(self.results['no_relro']):
                print(f"  {Fore.WHITE}{file_path}")
        else:
            print(f"  {Fore.GREEN}None found")
        
        # Files with Symbols = yes
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}Files with Symbols = YES ({len(self.results['has_symbols'])}):")
        print("-" * 80)
        if self.results['has_symbols']:
            for file_path in sorted(self.results['has_symbols']):
                print(f"  {Fore.WHITE}{file_path}")
        else:
            print(f"  {Fore.GREEN}None found")
        
        # Summary
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}{Style.BRIGHT}SUMMARY")
        print("=" * 80)
        total_issues = (len(self.results['no_canary']) + 
                       len(self.results['no_fortify']) + 
                       len(self.results['no_relro']))
        print(f"{Fore.WHITE}Total files with security issues: {total_issues}")
        print(f"{Fore.WHITE}Files with no canary: {len(self.results['no_canary'])}")
        print(f"{Fore.WHITE}Files with no FORTIFY: {len(self.results['no_fortify'])}")
        print(f"{Fore.WHITE}Files with no RELRO: {len(self.results['no_relro'])}")
        print(f"{Fore.WHITE}Files with symbols: {len(self.results['has_symbols'])}")

def main():
    """Main function to run the checksec reporter."""
    script_name = Path(__file__).name
    parser = argparse.ArgumentParser(
        description="Scan binary files using checksec and report files with specific security properties",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python3 {script_name} --dir ./arm64-v8a
  python3 {script_name} --dir /path/to/binaries/
  python3 {script_name} --dir ./arm64-v8a --checksec /path/to/checksec
        """
    )
    
    parser.add_argument(
        '--dir',
        type=str,
        required=True,
        help='Directory containing binary files to scan'
    )
    
    parser.add_argument(
        '--checksec',
        type=str,
        default='./checksec',
        help='Path to checksec executable (default: ./checksec)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='checksec_reporting v1.0'
    )
    
    args = parser.parse_args()
    
    # Validate directory exists
    target_dir = Path(args.dir)
    if not target_dir.exists():
        print(f"{Fore.RED}Error: Directory '{target_dir}' does not exist.")
        sys.exit(1)
    
    if not target_dir.is_dir():
        print(f"{Fore.RED}Error: '{target_dir}' is not a directory.")
        sys.exit(1)
    
    # Create and run reporter
    print(f"{Fore.CYAN}Running checksec on directory: {target_dir}")
    print(f"{Fore.CYAN}This may take a while...")
    
    reporter = ChecksecReporter(args.checksec)
    data = reporter.run_checksec(str(target_dir))
    reporter.analyze_results(data)
    reporter.print_results()

if __name__ == "__main__":
    main()
