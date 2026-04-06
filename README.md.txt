# 🔐 Log Analyzer for Threat Detection

## 📌 Overview
This project simulates a Security Operations Center (SOC) log analysis tool.
It detects suspicious login activity and potential brute-force attacks.

## ⚙️ Features
- Parses real-time log data
- Detects failed login attempts
- Identifies brute-force attacks
- Generates alert levels (HIGH, MEDIUM)
- Saves alerts to a file

## 🛠️ Tech Stack
- Python
- File Handling
- Data Structures

## ▶️ Usage
python analyzer.py logs.txt

## 📊 Example Output
[HIGH] 192.168.1.20 - Brute force suspected (3 attempts)

## 📁 Project Structure
- analyzer.py → main script
- logs.txt → input logs
- alerts.txt → generated alerts