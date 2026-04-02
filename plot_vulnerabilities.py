import json
import matplotlib.pyplot as plt
import numpy as np

def main():
    # try:
    #     with open("cross_referenced_results_pocgen.json", "r") as f:
    #         data = json.load(f)
    # except FileNotFoundError:
    #     print("Error: cross_referenced_results_pocgen.json not found.")
    #     return
        
    vuln_types = [
        "path_traversal",
        "prototype_pollution",
        "command_injection",
        "code_injection",
        "ReDoS"
    ]
    
    formatted_labels = [
        "Path Traversal", 
        "Prototype Pollution", 
        "Command Injection", 
        "Code Injection", 
        "ReDoS"
    ]
    
    categories = ["success", "failure", "false positive"]

    explodejs_results = {
        "Path Traversal": [81, 86, 0],
        "Prototype Pollution": [50, 130, 0],
        "Command Injection": [47, 45, 0],
        "Code Injection": [4, 31, 0],
        "ReDoS": [0, 86, 0]
    }

    agent_results = {
        "Path Traversal": [2, 18, 0],
        "Prototype Pollution": [8, 11, 1],
        "Command Injection": [8, 11, 1],
        "Code Injection": [6, 14, 0],
        "ReDoS": [4, 16, 0]
    }

    agent_4omini_results = { # 74% success rate
        "Path Traversal": [0, 18, 2],
        "Prototype Pollution": [2, 12, 6],
        "Command Injection": [4, 4, 12],
        "Code Injection": [6, 9, 5],
        "ReDoS": [3, 10, 7]
    }

    pocgen_results = {
        "Path Traversal": [133, 32, 2],
        "Prototype Pollution": [122, 31, 27],
        "Command Injection": [81, 10, 1],
        "Code Injection": [24, 10, 1],
        "ReDoS": [39, 44, 2]
    }

    pocgen_4omini_results = { # 77.14% success rate
        "Path Traversal": [148, 18, 1],
        "Prototype Pollution": [152, 25, 3],
        "Command Injection": [85, 6, 1],
        "Code Injection": [12, 7, 16],
        "ReDoS": [35, 49, 2]
    }

    # Combine data
    methods_dict = {
        "ExplodeJS": explodejs_results,
        "Mini-SWE-Agent": agent_results,
        "PoCGen (gpt-4o-mini)": pocgen_4omini_results,
        "Mini-SWE-Agent (gpt-4o-mini)": agent_4omini_results,
        "PoCGen": pocgen_results
    }
    
    all_methods = ["PoCGen", "ExplodeJS", "Mini-SWE-Agent", "PoCGen (gpt-4o-mini)", "Mini-SWE-Agent (gpt-4o-mini)"]
    all_method_counts = {m: {lbl: {cat: 0 for cat in categories} for lbl in formatted_labels} for m in all_methods}
    
    # 1. PoCGen data from JSON
    # for vuln, lbl in zip(vuln_types, formatted_labels):
    #     if vuln in data:
    #         for key, outcome in data[vuln].items():
    #             if outcome in categories:
    #                 all_method_counts["PoCGen"][lbl][outcome] += 1
                    
    # Fill the rest
    for m in ["ExplodeJS", "Mini-SWE-Agent", "PoCGen (gpt-4o-mini)", "Mini-SWE-Agent (gpt-4o-mini)", "PoCGen"]:
        res_dict = methods_dict[m]
        for lbl in formatted_labels:
            if lbl in res_dict:
                all_method_counts[m][lbl]["success"] = res_dict[lbl][0]
                all_method_counts[m][lbl]["failure"] = res_dict[lbl][1]
                all_method_counts[m][lbl]["false positive"] = res_dict[lbl][2]

    # Plotting setup
    fig = plt.figure(figsize=(18, 14))
    gs = fig.add_gridspec(4, 3)
    
    locations = {
        "PoCGen": gs[0:2, 0],
        "PoCGen (gpt-4o-mini)": gs[2:4, 0],
        "ExplodeJS": gs[1:3, 2],
        "Mini-SWE-Agent": gs[0:2, 1],
        "Mini-SWE-Agent (gpt-4o-mini)": gs[2:4, 1]
    }
    
    ax_dict = {}
    main_ax = None
    for method, pos in locations.items():
        if main_ax is None:
            ax = fig.add_subplot(pos)
            main_ax = ax
        else:
            ax = fig.add_subplot(pos, sharey=main_ax)
        ax_dict[method] = ax

    x = np.arange(len(formatted_labels))
    width = 0.75
    colors = {"success": "mediumseagreen", "failure": "orange", "false positive": "red"}
    
    for method, ax in ax_dict.items():
        method_counts = all_method_counts[method]
        
        # Calculate percentages
        percentages = {cat: [] for cat in categories}
        for lbl in formatted_labels:
            total = sum(method_counts[lbl][cat] for cat in categories)
            for cat in categories:
                if total > 0:
                    percentages[cat].append((method_counts[lbl][cat] / total) * 100)
                else:
                    percentages[cat].append(0)
                    
        bottoms = np.zeros(len(formatted_labels))
        
        for cat in categories:
            # We only label the first subplot to avoid duplicate legends
            label = cat.title() if method == "PoCGen" else None
            ax.bar(x, percentages[cat], width, label=label, bottom=bottoms, color=colors[cat])
            
            # Add text in the middle of each bar segment (absolute counts)
            for i in range(len(formatted_labels)):
                lbl = formatted_labels[i]
                pct_value = percentages[cat][i]
                abs_value = method_counts[lbl][cat]
                if pct_value > 0:
                    ax.text(x[i], bottoms[i] + pct_value / 2, f"{abs_value}", ha='center', va='center', color='black', fontweight='bold', fontsize=13)
                    
            bottoms += np.array(percentages[cat])
            

        
        # Calculate overall success rate
        total_success = sum(method_counts[lbl]["success"] for lbl in formatted_labels)
        total_all = sum(method_counts[lbl][cat] for lbl in formatted_labels for cat in categories)
        overall_success_rate = (total_success / total_all) * 100 if total_all > 0 else 0

        # Formulate the title to display
        display_title = method
        if method == "PoCGen":
            display_title = "PoCGen (gpt-5-mini)"
        elif method == "Mini-SWE-Agent":
            display_title = "Mini-SWE-Agent (gpt-5-mini)"
            
        display_title += f"\nSuccess Rate: {overall_success_rate:.1f}%"
            
        # Place the title at the top of the main ax
        ax.set_title(display_title, fontsize=16)
        
        ax.set_xticks(x)
        ax.set_xticklabels(formatted_labels, rotation=45, ha="right", fontsize=14)
        ax.set_ylim(0, 100)
    
    ax_dict["PoCGen"].set_ylabel('Success Rate (%)', fontsize=16)
    ax_dict["PoCGen (gpt-4o-mini)"].set_ylabel('Success Rate (%)', fontsize=16)

    # One legend for the whole figure, placed on top
    fig.legend(loc='upper right', bbox_to_anchor=(0.9, 0.9), fontsize=16, ncol=1)
    
    # Adjust layout to make room for legend and title
    # plt.subplots_adjust(hspace=1.5, top=0.85, bottom=0.25)
    plt.tight_layout()
    plt.savefig("vulnerability_plot.png", dpi=300)
    print("Plot saved to vulnerability_plot.png")

if __name__ == "__main__":
    main()
