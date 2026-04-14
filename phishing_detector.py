import re
import tkinter as tk
from tkinter import ttk
import requests
from datetime import datetime

# Replace with your NEW API key (never upload publicly)
API_KEY = "API KEY"

# Load blacklist
def load_blacklist():
    try:
        with open("blacklist.txt", "r") as f:
            return [line.strip() for line in f]
    except:
        return []

blacklist = load_blacklist()

# VirusTotal check
def check_virustotal(url):
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        if response.status_code == 200:
            return "✔ Submitted to VirusTotal"
        else:
            return "⚠️ VirusTotal request failed"
    except:
        return "⚠️ API error"

# Logging
def log_result(url, result):
    with open("scan_log.txt", "a") as f:
        f.write(f"{datetime.now()} | {url} → {result}\n")

# Main analysis
def analyze_url():
    url = entry.get()

    if not url.strip():
        output_label.config(text="⚠️ Enter a valid URL", fg="orange")
        return

    score = 0
    reasons = []

    # 🔥 Strong detection rules

    if len(url) > 50:
        score += 15
        reasons.append("Long URL")

    keywords = ["login", "verify", "bank", "secure", "update"]
    for word in keywords:
        if word in url.lower():
            score += 20
            reasons.append(f"Keyword: {word}")

    if re.match(r"^(http|https)://\d+\.\d+\.\d+\.\d+", url):
        score += 30
        reasons.append("IP-based URL")

    if url.count('.') > 3:
        score += 15
        reasons.append("Too many subdomains")

    if "@" in url:
        score += 30
        reasons.append("@ symbol")

    if "-" in url:
        score += 15
        reasons.append("Hyphen in domain")

    if url.startswith("file://"):
        score += 40
        reasons.append("Local phishing simulation")

    for bad in blacklist:
        if bad in url:
            score += 50
            reasons.append("Blacklisted domain")

    # Decision
    if score >= 60:
        result = "❌ HIGH RISK (Phishing)"
        color = "red"
    elif score >= 30:
        result = "⚠️ MEDIUM RISK"
        color = "orange"
    else:
        result = "✅ LOW RISK"
        color = "green"

    # Update UI
    output_label.config(text=f"{result}\nScore: {score}/100", fg=color)

    # Update risk bar
    risk_bar['value'] = score

    # Change color
    if score >= 60:
        risk_bar.configure(style="red.Horizontal.TProgressbar")
    elif score >= 30:
        risk_bar.configure(style="yellow.Horizontal.TProgressbar")
    else:
        risk_bar.configure(style="green.Horizontal.TProgressbar")

    # Show reasons
    reason_text.delete(1.0, tk.END)
    for r in reasons:
        reason_text.insert(tk.END, "- " + r + "\n")

    # API result
    vt_result = check_virustotal(url)
    reason_text.insert(tk.END, "\n" + vt_result)

    # Log result
    log_result(url, result)


# GUI Setup
root = tk.Tk()
root.title("Advanced Phishing Detection System")
root.geometry("700x500")

# Styles
style = ttk.Style()
style.configure("red.Horizontal.TProgressbar", background='red')
style.configure("yellow.Horizontal.TProgressbar", background='orange')
style.configure("green.Horizontal.TProgressbar", background='green')

# Title
tk.Label(root, text="🔐 Advanced Phishing Detector", font=("Arial", 16)).pack(pady=10)

# Input
entry = tk.Entry(root, width=70)
entry.pack(pady=10)

# Button
tk.Button(root, text="Analyze URL", command=analyze_url).pack(pady=5)

# Output
output_label = tk.Label(root, text="", font=("Arial", 14))
output_label.pack(pady=10)

# Risk bar
risk_bar = ttk.Progressbar(root, length=500, maximum=100)
risk_bar.pack(pady=10)

# Reasons
reason_text = tk.Text(root, height=12, width=85)
reason_text.pack(pady=10)

root.mainloop()
