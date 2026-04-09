import argparse
import glob
import json
import os
import sys

def main():
    parser = argparse.ArgumentParser(description="Sum up total prompt and completion tokens from pipeline JSON files.")
    parser.add_argument("directory", help="Input directory (e.g. output_gpt5mini_16022026)")
    args = parser.parse_args()

    directory = args.directory
    if not os.path.isdir(directory):
        print(f"Error: Directory '{directory}' does not exist.")
        sys.exit(1)

    pattern_flat = os.path.join(directory, "*", "RunnerResult_DefaultRefiner.json")
    files = glob.glob(pattern_flat)

    if not files:
        print(f"No files matching 'RunnerResult_DefaultRefiner.json' found in '{directory}/*'.")
        sys.exit(0)

    total_prompt_tokens = 0
    total_completion_tokens = 0
    durations = []
    ref_count = 0
    success_count = 0
    suc_ref_att = []
    ref_att = []

    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                entry = json.load(f)
                
                if isinstance(entry, dict):
                    refinement_attempts = 0
                    successful_refinement_attempts = 0          
                    attempt_durations = {}
                    if 'model' in entry:
                        model_data = entry['model']
                        if isinstance(model_data, dict):
                            total_prompt_tokens += model_data.get('totalPromptTokens', 0)
                            total_completion_tokens += model_data.get('totalCompletionTokens', 0)
                    if 'performanceTracker' in entry:
                        performance_tracker = entry['performanceTracker']
                        if isinstance(performance_tracker, dict):
                            for key, value in performance_tracker.items():
                                if key not in attempt_durations:
                                    attempt_durations[key] = 0
                                for measurements in value:
                                    attempt_durations[key] += measurements.get('duration', 0)
                    durations.append(attempt_durations)
                    if 'exploitAttempts' in entry and len(entry['exploitAttempts']) > 0:
                        if 'promptRefiners' in entry['exploitAttempts'][0]:
                            for refiner in entry['exploitAttempts'][0]['promptRefiners']:
                                refinement_attempts += refiner['refinementAttempts']
                                ref_count += 1
                                if 'exploitSuccessResult' in entry and entry['exploitSuccessResult']:
                                    successful_refinement_attempts += refiner['refinementAttempts']
                                    success_count += 1
                    if successful_refinement_attempts > 0:
                        suc_ref_att.append(successful_refinement_attempts)
                    ref_att.append(refinement_attempts)

        except Exception as e:
            print(f"Warning: Could not process file {file_path}. Error: {e}")

    print(f"Total Prompt Tokens: {total_prompt_tokens}")
    print(f"Total Completion Tokens: {total_completion_tokens}")
    # Calculate average duration for each key over all durations
    duration_results = {}
    print(len(durations))
    for duration in durations:
        for key, value in duration.items():
            if key not in duration_results:
                duration_results[key] = 0
            duration_results[key] += value
    for key, value in duration_results.items():
        print(f"Average duration for {key}: {(value / len(durations))}")

    print(f"Refinement average: {sum(ref_att) / len(ref_att)}")
    print(f"Success count: {success_count}")
    print(f"Successful refinement average: {sum(suc_ref_att) / len(suc_ref_att)}")
    print(f"Success in 1 attempt: {sum(1 for att in suc_ref_att if att == 1)}")
    print(f"Success in 2-10 attempts: {sum(1 for att in suc_ref_att if att >= 2 and att <= 10)}")
    print(f"Success in >10 attempts: {sum(1 for att in suc_ref_att if att > 10)}")
    
if __name__ == "__main__":
    main()
