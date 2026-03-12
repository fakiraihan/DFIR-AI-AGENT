#!/usr/bin/env python3
"""
Script to cut a large log file to a specified number of lines.
Efficiently handles very large files without loading everything into memory.
"""

import os
import sys


def cut_log_file(input_file, output_file, num_lines=1_000_000):
    """
    Cut a log file to the first N lines.
    
    Args:
        input_file: Path to the input log file
        output_file: Path to the output file
        num_lines: Number of lines to extract (default: 1,000,000)
    """
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found!")
        return False
    
    print(f"Reading from: {input_file}")
    print(f"Writing to: {output_file}")
    print(f"Extracting first {num_lines:,} lines...")
    
    line_count = 0
    
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as infile:
            with open(output_file, 'w', encoding='utf-8') as outfile:
                for line in infile:
                    if line_count >= num_lines:
                        break
                    outfile.write(line)
                    line_count += 1
                    
                    # Print progress every 100k lines
                    if line_count % 100_000 == 0:
                        print(f"Progress: {line_count:,} lines processed...")
        
        print(f"\nSuccess! Extracted {line_count:,} lines to '{output_file}'")
        
        # Show file size comparison
        input_size = os.path.getsize(input_file) / (1024**3)  # GB
        output_size = os.path.getsize(output_file) / (1024**3)  # GB
        print(f"Input file size: {input_size:.2f} GB")
        print(f"Output file size: {output_size:.2f} GB")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False


if __name__ == "__main__":
    # Configuration - Edit these values as needed
    INPUT_FILE = "input.log"  # Change this to your log file path
    OUTPUT_FILE = "output_1million.log"  # Output file name
    NUM_LINES = 1_000_000  # Number of lines to extract
    
    # Allow command line arguments
    if len(sys.argv) >= 2:
        INPUT_FILE = sys.argv[1]
    if len(sys.argv) >= 3:
        OUTPUT_FILE = sys.argv[2]
    if len(sys.argv) >= 4:
        try:
            NUM_LINES = int(sys.argv[3])
        except ValueError:
            print(f"Invalid number of lines: {sys.argv[3]}")
            sys.exit(1)
    
    if len(sys.argv) == 1:
        print("Usage:")
        print("  python cut_log_file.py <input_file> [output_file] [num_lines]")
        print("\nExample:")
        print("  python cut_log_file.py large_file.log output.log 1000000")
        print("\nOr edit the INPUT_FILE, OUTPUT_FILE, and NUM_LINES variables in the script.")
        print()
    
    # Run the cutting operation
    success = cut_log_file(INPUT_FILE, OUTPUT_FILE, NUM_LINES)
    sys.exit(0 if success else 1)
