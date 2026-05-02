# Phish X - Security Awareness Training Platform

Phish X is an AI-powered security awareness training tool for detecting phishing emails, vishing calls, and social engineering attacks. It uses machine learning (Naive Bayes, Random Forest, MFCC audio analysis) running locally - no data leaves your machine.

---

## Requirements

- **Windows 10 or 11**
- **Python 3.11** - download from [python.org/downloads](https://www.python.org/downloads/windows/)
  > During installation, tick **"Add Python to PATH"** - this is required

---

## Installation

### 1. Install Python 3.11

1. Go to [python.org/downloads](https://www.python.org/downloads/windows/)
2. Click **"Download Python 3.11.x"**
3. Run the installer
4. **Tick "Add Python to PATH"** at the bottom of the first screen
5. Click **Install Now**

Verify it worked - open a terminal and run:
```
python --version
```
You should see `Python 3.11.x`

### 2. Download Phish X

Click the green **Code** button above → **Download ZIP**, then extract it.

Or clone with Git:
```
git clone https://github.com/Oliver33Holland/Phish-X.git
cd Phish-X
```

> **Already cloned before?** Delete the old folder first, then clone again:
> ```
> rmdir /s /q Phish-X
> git clone https://github.com/Oliver33Holland/Phish-X.git
> cd Phish-X
> ```

### 3. Run the installer

Double-click **`install.cmd`**

This sets up the virtual environment and installs all dependencies automatically.

Or from a terminal:
```
install.cmd
```

---

## Running the App

### Option 1 - Desktop window (recommended)
Double-click **`Phish X - Desktop (No Browser).cmd`**

Opens Phish X in its own window. No browser required.

Or from a terminal:
```
"Phish X - Desktop (No Browser).cmd"
```

### Option 2 - Browser version (fallback)
Double-click **`Launch Phish X.cmd`**

Opens the same app in your default web browser at `http://127.0.0.1:8000`. Use this if the desktop window fails to open.

Or from a terminal:
```
"Launch Phish X.cmd"
```

> ⚠️ **The quote marks `"` are required when typing filenames with spaces in a terminal.** Double-clicking in File Explorer always works without them.

The app opens at `http://127.0.0.1:8000`

### From Python directly
```
venv\Scripts\python.exe phishx_app.py
```

---

## Features

| Feature | Description |
|---|---|
| **Email Phishing Detection** | Paste raw email source or plain text - scored by TF-IDF + Naive Bayes + Random Forest |
| **Vishing Detection** | Upload call recordings or paste transcripts to detect suspicious speech patterns using MFCC audio analysis |
| **Gamified Training** | Spot-the-phish mini-game with difficulty levels and scoring |
| **Campaign Manager** | Create and track phishing simulation campaigns with target lists |
| **Fake Login Pages** | Simulated credential-harvest pages for awareness demonstrations |
| **Analytics Dashboard** | Track click rates, game scores, and campaign results |

---

## Troubleshooting


**"Python not found" error**
Reinstall Python and make sure you ticked **"Add Python to PATH"** during setup.

**MP4 audio files won't transcribe**
Install ffmpeg from [ffmpeg.org/download.html](https://ffmpeg.org/download.html), add it to PATH, then restart. Alternatively paste the transcript manually into the text box provided.

**Port already in use**
Close any other running Phish X instances. The app tries ports 8000, 8001, 8080, and 8888 automatically.
