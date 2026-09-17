from typing import List, Dict, Any

SEVERITY_WEIGHTS = {
    ("CRITICAL", "FAIL"): 15,
    ("CRITICAL", "WARNING"): 8,
    ("HIGH", "FAIL"): 10,
    ("HIGH", "WARNING"): 5,
    ("MEDIUM", "FAIL"): 6,
    ("MEDIUM", "WARNING"): 3,
    ("LOW", "FAIL"): 3,
    ("LOW", "WARNING"): 1,
}

def calculate_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    base_score = 100
    deductions = 0
    
    passed_count = 0
    warning_count = 0
    failed_count = 0
    
    category_stats = {}

    for f in findings:
        status = f.get("status", "PASS")
        severity = f.get("severity", "LOW")
        cat = f.get("category", "General")

        if cat not in category_stats:
            category_stats[cat] = {"passed": 0, "warning": 0, "failed": 0, "total": 0}

        category_stats[cat]["total"] += 1

        if status == "PASS":
            passed_count += 1
            category_stats[cat]["passed"] += 1
        elif status == "WARNING":
            warning_count += 1
            category_stats[cat]["warning"] += 1
            deductions += SEVERITY_WEIGHTS.get((severity, "WARNING"), 2)
        elif status == "FAIL":
            failed_count += 1
            category_stats[cat]["failed"] += 1
            deductions += SEVERITY_WEIGHTS.get((severity, "FAIL"), 5)

    final_score = max(0, min(100, base_score - deductions))

    # Calculate letter grade
    if final_score >= 95:
        grade = "A+"
        grade_label = "Exemplary"
        grade_color = "#10b981" # emerald
    elif final_score >= 85:
        grade = "A"
        grade_label = "Secure"
        grade_color = "#22c55e" # green
    elif final_score >= 70:
        grade = "B"
        grade_label = "Adequate"
        grade_color = "#3b82f6" # blue
    elif final_score >= 50:
        grade = "C"
        grade_label = "Needs Improvement"
        grade_color = "#f59e0b" # amber
    elif final_score >= 35:
        grade = "D"
        grade_label = "Weak Posture"
        grade_color = "#f97316" # orange
    else:
        grade = "F"
        grade_label = "Vulnerable"
        grade_color = "#ef4444" # red

    return {
        "score": final_score,
        "grade": grade,
        "grade_label": grade_label,
        "grade_color": grade_color,
        "status_counts": {
            "passed": passed_count,
            "warning": warning_count,
            "failed": failed_count,
            "total": len(findings)
        },
        "category_stats": category_stats
    }
