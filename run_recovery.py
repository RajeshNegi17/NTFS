#!/usr/bin/env python3
"""
Simple wrapper script to run NTFS file recovery
"""

import subprocess
import sys
import os

def main():
    if len(sys.argv) < 2:
        print("Usage: python run_recovery.py <image_file> [options]")
        print("\nExamples:")
        print("  python run_recovery.py new.img")
        print("  python run_recovery.py new.img --recover-all")
        print("  python run_recovery.py new.img --cluster-size 8192")
        print("\nAvailable options:")
        print("  --recover-all     : Recover all files without prompting")
        print("  --cluster-size N  : Set cluster size in bytes (default: 4096)")
        print("  --mft-offset N    : Set MFT offset in bytes (auto-detected if not provided)")
        print("  --output-dir DIR  : Set output directory (default: output)")
        print("  --max-file-size N : Set maximum file size to recover in bytes (default: 100MB)")
        sys.exit(1)
    
    image_file = sys.argv[1]
    
    if not os.path.exists(image_file):
        print(f"Error: Image file '{image_file}' not found.")
        sys.exit(1)
    
    # Build command
    cmd = [sys.executable, "extract.py"] + sys.argv[1:]
    
    print(f"Running: {' '.join(cmd)}")
    print("-" * 50)
    
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\nError: Command failed with exit code {e.returncode}")
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)

if __name__ == "__main__":
    main() 