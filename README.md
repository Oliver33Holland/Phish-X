# Phish X – AI-Powered Phishing Awareness Training

Phish X is a desktop security awareness training platform that uses machine learning to detect phishing emails, vishing calls, and AI-generated threats.

---

## Quick Start

### Step 1 – Install Python

1. Go to [python.org/downloads](https://www.python.org/downloads/)
2. Download the latest **Python 3.11** (or newer) installer
3. Run the installer — **tick "Add Python to PATH"** before clicking Install

### Step 2 – Download Phish X

Clone or download this repository as a ZIP and extract it to a folder on your computer.

### Step 3 – Install dependencies

Double-click **`install.cmd`**

> If Windows asks for administrator permission, click **Yes** — this is needed to add an antivirus exclusion so the app runs correctly.

This will:
- Create a Python virtual environment
- Install all required packages automatically

### Step 4 – Run the app

Double-click **`Phish X - Desktop (No Browser).cmd`**

The Phish X window will open. No browser or internet connection required.

---

## Features

| Feature | Description |
|---|---|
| **Phishing Detection** | Analyse emails using TF-IDF + Naive Bayes + Random Forest ML models |
| **Vishing Detection** | Upload call recordings or paste transcripts to detect suspicious speech patterns |
| **Gamified Training** | Interactive mini-game — spot the phishing email and earn points |
| **Campaign Manager** | Create and manage phishing simulation campaigns |
| **Fake Login Pages** | Simulated login pages for awareness training |
| **Analytics Dashboard** | Track results, scores, and campaign outcomes |

---

## Requirements

- Windows 10 or 11
- Python 3.11 or newer ([python.org](https://www.python.org/downloads/))
- Internet connection (first run only, to install packages)

All Python dependencies are listed in `requirements.txt` and installed automatically by `install.cmd`.

---

## Folder Structure

```
Phish X/
├── app/                          # Backend – FastAPI routes and ML models
├── static/                       # Frontend – HTML/CSS/JS UI
├── data/                         # Runtime data (campaigns, analytics)
├── install.cmd                   # One-click installer
├── Phish X - Desktop (No Browser).cmd   # Desktop launcher
├── Launch Phish X.cmd            # Browser launcher (alternative)
├── requirements.txt              # Python dependencies
└── run_web.py                    # Web server entry point
```

---

## Troubleshooting

**The app won't open / antivirus blocks it**
Run `install.cmd` as administrator — it adds an exclusion so the app isn't blocked.

**"Python not found" error**
Make sure Python is installed and you ticked "Add Python to PATH" during installation.

**MP4/audio files won't transcribe**
Install ffmpeg from [ffmpeg.org/download.html](https://ffmpeg.org/download.html) and add it to your PATH. Alternatively, paste the call transcript manually into the text box.
