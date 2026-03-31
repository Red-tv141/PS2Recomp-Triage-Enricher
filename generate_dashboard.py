import re
import os

def parse_report(report_path):
    """
    Parses the text report to extract data for the dashboard.
    """
    if not os.path.exists(report_path):
        print(f"[Error] Report file not found: {report_path}")
        return None

    with open(report_path, 'r', encoding='utf-8') as f:
        content = f.read()

    data = {}
    
    # 1. Extract General Overview info from Section 1
    try:
        data['elf_hash'] = re.search(r"ELF Hash\s+:\s+(\w+)", content).group(1)
        data['total_funcs'] = re.search(r"Total Functions \(ELF\):\s+(\d+)", content).group(1)
        data['enriched'] = re.search(r"Enriched \(our scope\)\s+:\s+(\d+)", content).group(1)
        data['code_size'] = re.search(r"Total Code Size\s+:\s+([\d,]+ bytes \([\d.]+ KB\))", content).group(1)
    except AttributeError:
        print("[Error] Could not parse basic info. Verify the report format.")
        return None

    # 2. Extract Category Distribution data
    cat_matches = re.findall(r"(\w+)\s+:\s+(\d+)\s+\(\s*([\d.]+%)\)\s+([\d.]+ KB)", content)
    data['categories'] = [{"name": m[0], "count": m[1], "perc": m[2], "size": m[3]} for m in cat_matches]

    # 3. Extract Disposition stats (RECOMPILE/STUB/SKIP)
    data['disposition'] = {}
    disp_section = re.search(r"Disposition:(.*?)\n\n", content, re.DOTALL)
    if disp_section:
        disp_matches = re.findall(r"(\w+)\s+:\s+(\d+)", disp_section.group(1))
        data['disposition'] = {m[0]: m[1] for m in disp_matches}

    # 4. Extract Top Functions from Section 5c (Global Writers)
    # Splits content based on the Section 5c header found in the report
    table_match = re.split(r"5c\. GLOBAL WRITERS WITHOUT STACK FRAME.*?\n-+\n", content, flags=re.DOTALL)
    data['top_funcs'] = []
    
    if len(table_match) > 1:
        # Matches the specific column layout of your report
        row_pattern = r"^\s*\d*\s*(0x[0-9A-F]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\w+)\s+(.*)$"
        table_rows = table_match[1].strip().split('\n')
        
        for row in table_rows:
            m = re.match(row_pattern, row.strip())
            if m:
                data['top_funcs'].append({
                    "addr": m.group(1),
                    "size": m.group(2),
                    "math": m.group(4),
                    "branch": m.group(5),
                    "calls": m.group(6),
                    "cat": m.group(7),
                    "name": m.group(8).strip()
                })

    return data

def generate_html(data, output_path):
    """
    Generates a stylized HTML dashboard based on the parsed data.
    """
    if not data: return

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Dark Cloud 2 - Recompilation Dashboard</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 30px; line-height: 1.6; }}
            .container {{ max-width: 1200px; margin: auto; }}
            h1, h2 {{ color: #4fc3f7; border-bottom: 1px solid #333; padding-bottom: 10px; }}
            .header-meta {{ color: #888; font-size: 14px; margin-bottom: 20px; }}
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }}
            .card {{ background: #252525; padding: 20px; border-radius: 8px; border-top: 4px solid #007acc; box-shadow: 0 4px 10px rgba(0,0,0,0.3); }}
            .card h3 {{ margin: 0; font-size: 13px; color: #aaa; text-transform: uppercase; letter-spacing: 1px; }}
            .card .val {{ font-size: 28px; font-weight: bold; margin: 10px 0; color: #ffb74d; }}
            .card .sub {{ font-size: 12px; color: #666; }}
            table {{ width: 100%; border-collapse: collapse; background: #252525; border-radius: 8px; overflow: hidden; margin-top: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; font-size: 13px; }}
            th {{ background: #333; color: #4fc3f7; text-transform: uppercase; font-size: 11px; }}
            tr:hover {{ background: #2d2d2d; }}
            code {{ color: #ce9178; font-family: 'Consolas', monospace; }}
            .disposition-recompile {{ border-top-color: #2e7d32; }}
            .disposition-skip {{ border-top-color: #c62828; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Dark Cloud 2 Analysis Dashboard</h1>
            <div class="header-meta">
                <strong>ELF Hash:</strong> {data['elf_hash']} | 
                <strong>Total Code Size:</strong> {data['code_size']}
            </div>
            
            <div class="grid">
                <div class="card"><h3>Total ELF Functions</h3><div class="val">{data['total_funcs']}</div></div>
                <div class="card"><h3>Enriched Scope</h3><div class="val">{data['enriched']}</div></div>
                <div class="card disposition-recompile"><h3>To Recompile</h3><div class="val">{data['disposition'].get('RECOMPILE', 0)}</div></div>
                <div class="card disposition-skip"><h3>Skipped</h3><div class="val">{data['disposition'].get('SKIP', 0)}</div></div>
            </div>

            <h2>Category Distribution</h2>
            <div class="grid">
                {"".join(f'<div class="card"><h3>{c["name"]}</h3><div class="val">{c["count"]}</div><div class="sub">{c["perc"]} of scope | {c["size"]}</div></div>' for c in data['categories'])}
            </div>

            <h2>Global Writers (Potential Performance Bottlenecks)</h2>
            <p style="font-size: 14px; color: #888;">Functions without stack frames that modify global memory addresses.</p>
            <table>
                <thead>
                    <tr>
                        <th>Address</th>
                        <th>Math Ops</th>
                        <th>Branches</th>
                        <th>Calls</th>
                        <th>Category</th>
                        <th>Function Name</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'<tr><td><code>{f["addr"]}</code></td><td>{f["math"]}</td><td>{f["branch"]}</td><td>{f["calls"]}</td><td>{f["cat"]}</td><td>{f["name"]}</td></tr>' for f in data['top_funcs'])}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[Success] Dashboard generated: {os.path.abspath(output_path)}")

if __name__ == "__main__":
    # Ensure Dark_Cloud_2_report.txt is in the same directory
    report_data = parse_report("Dark_Cloud_2_report.txt")
    if report_data:
        generate_html(report_data, "Dark_Cloud_2_dashboard.html")
