import json
import os
from collections import Counter

def generate_html_report(json_path, output_html):
    if not os.path.exists(json_path):
        print(f"[Error] File not found: {json_path}")
        return

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    stats = data.get("statistics", {})
    functions = data.get("functions", [])

    # Process Categories
    categories = Counter(f["category"] for f in functions)
    
    # Process Hazards (extract lists of dangerous functions)
    jump_tables = [f for f in functions if "COMPLEX_CONTROL_FLOW" in f.get("tags", [])]
    vcallms_funcs = [f for f in functions if "VU0_MICROCODE" in f.get("tags", [])]
    acc_hazards = [f for f in functions if "ACC_PRECISION_HAZARD" in f.get("tags", [])]

    # HTML Generation
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PS2Recomp Triage Dashboard</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e1e; color: #d4d4d4; margin: 0; padding: 20px; }}
            h1, h2, h3 {{ color: #569cd6; }}
            .container {{ max-width: 1200px; margin: auto; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
            .stat-box {{ background-color: #252526; border-left: 4px solid #007acc; padding: 15px; border-radius: 4px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }}
            .stat-box h3 {{ margin: 0 0 10px 0; font-size: 14px; color: #9cdcfe; text-transform: uppercase; }}
            .stat-box .number {{ font-size: 24px; font-weight: bold; color: #ce9178; }}
            
            .hazard-section {{ background-color: #2d2d2d; padding: 20px; margin-bottom: 20px; border-radius: 5px; border-left: 4px solid #d16969; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #404040; }}
            th {{ background-color: #333333; color: #dcdcaa; }}
            tr:hover {{ background-color: #383838; }}
            .tag {{ display: inline-block; padding: 3px 8px; margin: 2px; background-color: #4d4d4d; border-radius: 12px; font-size: 12px; color: #d4d4d4; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>PS2Recomp Triage Dashboard</h1>
            <p><strong>ELF Hash:</strong> {data.get('elf_hash')} | <strong>MainLoop Shield:</strong> {data.get('mainloop_shield_size')} functions protected</p>
            
            <h2>Global Statistics</h2>
            <div class="stats-grid">
                <div class="stat-box"><h3>Total Functions</h3><div class="number">{stats.get('total_functions')}</div></div>
                <div class="stat-box"><h3>Enriched Count</h3><div class="number">{stats.get('enriched_count')}</div></div>
                <div class="stat-box" style="border-left-color: #4CAF50;"><h3>Safe Leaf Functions</h3><div class="number">{stats.get('safe_leaf')}</div></div>
                <div class="stat-box" style="border-left-color: #ff9800;"><h3>MMIO Accesses</h3><div class="number">{stats.get('mmio_access')}</div></div>
                <div class="stat-box" style="border-left-color: #f44336;"><h3>Jump Tables (Risk)</h3><div class="number">{stats.get('jump_tables')}</div></div>
                <div class="stat-box" style="border-left-color: #e91e63;"><h3>VU0 Microcode (Risk)</h3><div class="number">{stats.get('vcallms')}</div></div>
            </div>

            <h2>Function Categories</h2>
            <div class="stats-grid">
                {"".join(f'<div class="stat-box"><h3>{cat}</h3><div class="number">{count}</div></div>' for cat, count in categories.most_common())}
            </div>

            <h2>Critical Hazards (Manual Review Required)</h2>
            
            <div class="hazard-section">
                <h3 style="color: #d16969;">VU0 Microcode Functions (vcallms)</h3>
                <p>These functions execute inline VU0 macro-instructions and usually require manual C++ vector implementation.</p>
                <table>
                    <tr><th>Address</th><th>Name</th><th>Size (Instr)</th><th>FPU Ops</th></tr>
                    {"".join(f'<tr><td>{f.get("address")}</td><td>{f.get("name")}</td><td>{f.get("size")}</td><td>{f.get("metrics", {}).get("fpu_ops")}</td></tr>' for f in vcallms_funcs)}
                </table>
            </div>

            <div class="hazard-section">
                <h3 style="color: #d8a0df;">Complex Control Flow (Jump Tables)</h3>
                <p>Functions containing indirect jumps ('jr' without 'ra'). The static recompiler may fail to resolve the switch cases.</p>
                <table>
                    <tr><th>Address</th><th>Name</th><th>Category</th><th>Size (Instr)</th></tr>
                    {"".join(f'<tr><td>{f.get("address")}</td><td>{f.get("name")}</td><td>{f.get("category")}</td><td>{f.get("size")}</td></tr>' for f in jump_tables[:50])}
                    {f'<tr><td colspan="4">... and {len(jump_tables) - 50} more.</td></tr>' if len(jump_tables) > 50 else ""}
                </table>
            </div>
            
        </div>
    </body>
    </html>
    """

    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[Success] Dashboard generated: {os.path.abspath(output_html)}")

if __name__ == "__main__":
    generate_html_report("triage_map.json", "ps2recomp_dashboard.html")