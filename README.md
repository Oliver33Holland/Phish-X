# Phish X - Security Awareness Training Platform

Phish X is a desktop security awareness training tool that uses machine learning to detect phishing emails, vishing calls, and AI-generated threats. All processing runs locally with no data leaving the machine.

---

## Requirements

- Windows 10 or 11
- Python 3.11 or newer - download from [python.org/downloads](https://www.python.org/downloads/windows/)

> During installation, tick **"Add Python to PATH"** - this is required for the app to work

---

## Installation

### Step 1 - Install Python 3.11

1. Go to [python.org/downloads](https://www.python.org/downloads/windows/)
2. Download and run the installer
3. Tick **"Add Python to PATH"** before clicking Install Now

Verify it worked by opening a terminal and running:
```
python --version
```
You should see `Python 3.11.x`

### Step 2 - Download Phish X

Download and extract the ZIP, or clone with Git:
```
git clone https://github.com/Oliver33Holland/Phish-X.git
cd Phish-X
```

> Already cloned before? Delete the old folder first:
> ```
> rmdir /s /q Phish-X
> git clone https://github.com/Oliver33Holland/Phish-X.git
> cd Phish-X
> ```

### Step 3 - Install dependencies

Double-click **`install.cmd`**

This sets up a Python virtual environment and installs all packages automatically. Wait for "Installation complete!" then press any key.

Or from a terminal:
```
install.cmd
```

---

## Running the App

### Option 1 - Desktop window (recommended)
Double-click **`Phish X - Desktop (No Browser).cmd`**

Opens Phish X in its own window. No browser required.

From a terminal:
```
"Phish X - Desktop (No Browser).cmd"
```

### Option 2 - Browser version (fallback)
Double-click **`Launch Phish X.cmd`**

Opens the same app in your default browser at `http://127.0.0.1:8000`. Use this if the desktop window does not open.

From a terminal:
```
"Launch Phish X.cmd"
```

> **Note:** Quote marks are required when typing filenames with spaces in a terminal. Double-clicking in File Explorer always works without them.

---

## Features

| Feature | Description |
|---|---|
| **Email Phishing Detection** | Paste raw email source or plain text - scored by TF-IDF, Naive Bayes and Random Forest |
| **Vishing Detection** | Upload call recordings or paste transcripts to detect suspicious speech patterns |
| **Gamified Training** | Spot-the-phish mini-game with difficulty levels and scoring |
| **Campaign Manager** | Create and manage phishing simulation campaigns with target lists |
| **Fake Login Pages** | Simulated login pages for awareness training demonstrations |
| **Analytics Dashboard** | Track click rates, game scores and campaign results |

---

## Troubleshooting

**"Python not found" error**
Reinstall Python and make sure you ticked "Add Python to PATH" during setup.

**App window does not open**
Use the browser version instead - double-click `Launch Phish X.cmd`.

**Missing packages error**
Run `install.cmd` again to reinstall all dependencies.

**MP4 files will not transcribe**
Install ffmpeg from [ffmpeg.org/download.html](https://ffmpeg.org/download.html) and add it to PATH, then restart the app. You can also paste the transcript manually into the text box.

**Port already in use**
Close any other running Phish X instances. The app tries ports 8000, 8001, 8080 and 8888 automatically.
