import argparse
import glob
import os
import sys
import re

def main():
    parser = argparse.ArgumentParser(description="Sum up total cost from output_DefaultRefiner.log files.")
    parser.add_argument("directory", help="Input directory (e.g. output_minisweagent_22022026)")
    args = parser.parse_args()

    directory = args.directory
    if not os.path.isdir(directory):
        print(f"Error: Directory '{directory}' does not exist.")
        sys.exit(1)

    pattern_flat = os.path.join(directory, "*", "output_DefaultRefiner.log")
    files = glob.glob(pattern_flat)

    if not files:
        print(f"No matching 'output_DefaultRefiner.log' files found in '{directory}'.")
        sys.exit(0)

    total_cost = 0.0
    # Match the line format exactly, capturing the float value
    regex_pattern = re.compile(r"mini-swe-agent \(step \w+, \$([0-9.]+)\):")

    for file_path in files:
        try:
            last_cost = None
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    match = regex_pattern.search(line)
                    if match:
                        last_cost = float(match.group(1))
            
            if last_cost is not None:
                total_cost += last_cost
        except Exception as e:
            print(f"Warning: Could not process file {file_path}. Error: {e}")

    print(f"Total Cost: ${total_cost:.2f}")

if __name__ == "__main__":
    main()
