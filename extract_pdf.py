import pdfplumber
import sys
import json
import re
import csv
import os
import time

def extract_results(pdf_path, semester):
    results = []

    with pdfplumber.open(pdf_path) as pdf:
        lines = []
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                lines.extend([line.strip() for line in text.split('\n') if line.strip()])

    print("🔍 Total lines extracted:", len(lines), file=sys.stderr)

    for idx, line in enumerate(lines):
        if any(keyword in line.lower() for keyword in ['note', 'subject', 'htno', 'externals']):
            continue

        parts = line.split()

        # ✅ Handle S.No. only if more than 6 parts exist
        if re.match(r'^\d+$', parts[0]) and len(parts) > 6:
            parts = parts[1:]

        if len(parts) < 6:
            print(f"⏭️ Line {idx+1}: Not enough parts — {line}", file=sys.stderr)
            continue

        regno = parts[0]
        subcode = parts[1]
        grade = parts[-2].upper()
        credits = parts[-1]
        subname = ' '.join(parts[2:-3])

        # ✅ Normalize grades
        if grade in ["ABSENT", "AB"]:
            grade = "Ab"
        elif grade in ["COMPLE", "COMPLETED"]:
            grade = "Completed"
        elif grade in ["NOTCOMPLETED", "NOT CO", "NOTCO", "NOT", "NC"]:
            grade = "Not Completed"

        # ✅ Validation
        if not re.match(r'^[0-9A-Z]{10}$', regno):
            print(f"⏭️ Line {idx+1}: Invalid regno — {regno}", file=sys.stderr)
            continue
        if not subcode.startswith('R23'):
            print(f"⏭️ Line {idx+1}: Not R23 subcode — {subcode}", file=sys.stderr)
            continue
        if grade not in ['S', 'A', 'B', 'C', 'D', 'E', 'F', 'Ab', 'Completed', 'Not Completed']:
            print(f"⏭️ Line {idx+1}: Invalid grade — {grade}", file=sys.stderr)
            continue
        if not credits.replace('.', '', 1).isdigit():
            print(f"⏭️ Line {idx+1}: Invalid credits — {credits}", file=sys.stderr)
            continue

        results.append({
            "regno": regno,
            "subcode": subcode,
            "subname": subname,
            "grade": grade,
            "credits": float(credits)
        })

        print(f"✅ Line {idx+1}: Stored → {regno} - {subcode} - {grade} - {credits}", file=sys.stderr)

    # ✅ Save to CSV
    if not os.path.exists('output'):
        os.makedirs('output')

    filename = f'output/{semester}_{int(time.time())}.csv'
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['regno', 'subcode', 'subname', 'grade', 'credits'])
        for row in results:
            writer.writerow([row['regno'], row['subcode'], row['subname'], row['grade'], row['credits']])

    return results

# ✅ Entry point — clean stdout for Node.js
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[]")
        sys.exit()

    path = sys.argv[1]
    semester = sys.argv[2]
    parsed = extract_results(path, semester)
    print(json.dumps(parsed, ensure_ascii=False))  # 👈 JSON for Node.js
