# KayaBot 🤖

> 🇬🇧 English | [🇮🇷 فارسی](README.md)

An auto-monitoring and auto-proposal bot for [kaya.ir](https://kaya.ir).

Built with Selenium and headless Chrome, KayaBot logs into your account, watches the
list of newly posted projects, and automatically submits proposals to the projects
that match your filters.

---

## ✨ Features

- **Cookie-based login** — credentials are used once, then stored cookies are reused for up to 30 days (SQLite).
- **Continuous monitoring** — re-checks the project list on a fixed interval and picks up new posts.
- **Country filter** — projects from a configurable list of countries are skipped.
- **Smart pricing** — reads a price range (e.g. `250 - 300`) and submits its **average** as your bid.
- **Automatic proposals** — fills in price, delivery time and description, then clicks submit.
- **Duplicate detection** — projects you already proposed on are never opened twice.
- **Stealth mode** — CDP scripts that reduce basic bot detection.
- **Full logging** — everything is written to the console and to `kaya_monitor.log`.

---

## 📁 Project Structure

```
kayabot/
├── main.py            # Bot logic (auth, monitoring, proposal submission)
├── descriptions.txt   # Proposal text sent with every submission
├── requirements.txt   # Python dependencies
├── README.md          # Persian version (default)
└── README.en.md       # This file (English)
```

Runtime files generated while the bot runs (ignored by git):

| File | Purpose |
|------|---------|
| `kaya.db` | SQLite database holding your login cookies |
| `kaya_monitor.log` | Bot log |
| `chromedriver.log` | ChromeDriver log |
| `*.png` | Debug screenshots captured on errors |

---

## ⚙️ Requirements

- Python 3.8+
- Google Chrome

---

## 🚀 Installation

```bash
git clone https://github.com/p-a-x-e-m/KayaBot.git
cd KayaBot
pip install -r requirements.txt
```

To install Chrome manually:

```bash
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
```

---

## 🔧 Configuration

### 1. Login credentials

Credentials are read from **environment variables**, so your password never lives in the code.
The cookie-encryption key is generated separately:

```bash
# Generate the encryption key (once)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Linux / macOS:

```bash
export KAYA_USERNAME="your_username"   # phone number or email
export KAYA_PASSWORD="your_password"
export KAYA_COOKIE_KEY="<key generated above>"
```

Windows (PowerShell):

```powershell
$env:KAYA_USERNAME = "your_username"
$env:KAYA_PASSWORD = "your_password"
$env:KAYA_COOKIE_KEY = "<key generated above>"
```

> ℹ️ If these are missing, the bot stops immediately with a clear error.
> Session cookies are encrypted with `KAYA_COOKIE_KEY`; `kaya.db` only ever
> holds ciphertext. Changing the key invalidates the stored cookies and
> triggers a fresh login.

### Optional variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `KAYA_DEBUG` | `false` | Run Chrome with a visible window (troubleshooting) |
| `KAYA_DEBUG_ARTIFACTS` | `false` | Save screenshots of authenticated pages on error |
| `KAYA_CHECK_INTERVAL` | `5` | Minutes between project checks |
| `KAYA_LOG_LEVEL` | `INFO` | Log level (`DEBUG` for more detail) |
| `KAYA_NO_SANDBOX` | `false` | Disable Chrome's sandbox — root in a container only |

> ⚠️ Debug screenshots can capture your account details. Enable temporarily only.

### 2. Target project list

```python
self.target_url = "https://kaya.ir/projects/jobs/17"
```

### 3. Excluded countries

```python
self.excluded_countries = ['India', 'Pakistan', 'Bangladesh']
```

### 4. Proposal text

Write your own proposal in [`descriptions.txt`](descriptions.txt).
(The default version introduces you, offers a 20% discount for a first project,
and invites the client to discuss further.)

### 5. Check interval

At the bottom of `main.py`:

```python
monitor.monitor_new_projects(check_interval=5)  # every 5 minutes
```

---

## ▶️ Usage

```bash
python main.py
```

Sample output:

```
Starting Kaya.ir Project Monitor
Monitoring URL: https://kaya.ir/projects/jobs/17
Excluded countries: ['India', 'Pakistan', 'Bangladesh']
Press Ctrl+C to stop
```

Press `Ctrl+C` to stop the bot; the browser session is closed and cleaned up.

---

## 🧠 How It Works

```
┌──────────────────────────────┐
│  Authenticate (stored cookie │
│  or manual login)            │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│  Load the project list       │◄── every check_interval minutes
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│  Extract title, price,       │
│  country and post time;      │
│  apply country & time filter │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│  Drop already-seen projects  │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│  Open the proposal form, fill │
│  price / period / description │
│  and submit                   │
└──────────────────────────────┘
```

---

## 📌 Notes

- **First run:** a browser window opens so you can log in once and let the cookies be saved.
- Project times are interpreted as **HH:MM on the current day**; if the listed time is
  ahead of the current time, it is treated as yesterday.
- If the stored cookies expire, the bot automatically falls back to manual login.
- The bot starts with `debug=True` (visible browser window). Set it to `False`
  for headless runs.

---

## ⚖️ Disclaimer

Use this tool at your own responsibility. Make sure you comply with the terms of
service of the target site and keep your usage fair.

---

## 📄 License

MIT
