import os
import json
import sys

def evaluate_risk(answers):
    risk_score = 0
    flags = []

    if answers.get("involves_ai", False):
        risk_score += 3
        flags.append("AI/ML component")
    if answers.get("processes_pii", False):
        risk_score += 5
        flags.append("Personal data")
    if answers.get("dual_use", False):
        risk_score += 10
        flags.append("🚨 Dual-use technology")
    if answers.get("safety_critical", False):
        risk_score += 8
        flags.append("Safety-critical")

    if "purely documentation" in answers.get("safe_changes", []):
        return "LOW", "No ethical concerns detected."

    if risk_score >= 10:
        return "HIGH", " | ".join(flags)
    elif risk_score >= 5:
        return "MEDIUM", " | ".join(flags)
    else:
        return "LOW", "Minor changes"

# Parse comment or form submission here (simplified)
# In real use, you'd parse the actual comment body
answers = json.loads(sys.argv[1])  # passed from workflow
level, reason = evaluate_risk(answers)

print(f"RISK_LEVEL={level}")
print(f"REASON={reason}")