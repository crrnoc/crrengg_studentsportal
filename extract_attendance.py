import sys
import os
import pdfplumber
import csv
import json
import re

if len(sys.argv) < 3:
    print("Usage: extract_attendance.py <pdf_path> <semester>")
    sys.exit(1)

pdf_path = sys.argv[1]
semester = sys.argv[2]
results = []

csv_name = os.path.splitext(os.path.basename(pdf_path))[0] + ".csv"
csv_path = os.path.join("uploads", csv_name)

def parse_attendance_line(line):
    # Match regno like 23B81A4501 followed by groups of attendance like 12/14 28/35 ... then total like 110/133 and percent
    match = re.match(r"^(2[0-9]B81A\d{4})\s+(?:\d+/\d+\s+){6,8}(\d+)/(\d+)\s+([\d.]+)", line)
    if match:
        regno = match.group(1)
        present = int(match.group(2))
        total = int(match.group(3))
        percent = float(match.group(4))
        return [regno, semester, total, present, percent]
    return None

with pdfplumber.open(pdf_path) as pdf:
    for page in pdf.pages:
        text = page.extract_text()
        if not text:
            continue
        lines = text.split("\n")
        for line in lines:
            parsed = parse_attendance_line(line.strip())
            if parsed:
                results.append(parsed)

# ✅ Save CSV
with open(csv_path, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['regno', 'semester', 'total_classes', 'attended_classes', 'percentage'])
    writer.writerows(results)

# ✅ Output JSON to Node.js
print(json.dumps(results))
