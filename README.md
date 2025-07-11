# NodeSniff Agent

NodeSniff Agent is a lightweight server metrics collector for the NodeSniff monitoring system.  
The agent collects and securely sends metrics to your NodeSniff backend over HTTPS.

**License:** GNU GPL v3 (non-commercial use only)

---

## Features

- Collects CPU, RAM, disk, network, and OS metrics (extensible via Python plugins)
- Secure HTTPS metric transmission with HMAC authentication
- CLI modes for install, remove, cleanup
- Systemd integration with `/usr/bin/nsagent` symlink
- Recommended setup as dedicated unprivileged `nodesniff` user

---

## Requirements

- Python 3.7+
- Linux (x86, ARM, etc.)
- Python packages:
  - `psutil`
  - `PyYAML`
  - `requests`
  - `setuptools` (required for some plugin systems)

Install dependencies:
```sh
pip install -r requirements.txt
```

---

## Installation and Registration (as dedicated user)

### 1. Create dedicated system user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin nodesniff
```

### 2. Register the agent (as root)

```bash
sudo ./nsagent.py
```

If Python or packages are missing:
```bash
sudo apt install python3-pip
pip3 install -r requirements.txt
# or, for Raspberry Pi and similar:
sudo pip3 install --break-system-packages PyYAML
```

Paste your company key into:
```bash
sudo nano /etc/nodesniff/nsagent.token
```

Run agent again:
```bash
sudo ./nsagent.py
```

### 3. Set ownership for runtime directories

```bash
sudo chown -R nodesniff:nodesniff /etc/nodesniff
sudo chown -R nodesniff:nodesniff /usr/lib/nodesniff
sudo chown nodesniff:nodesniff /var/log/nsagent.log
```
*(Skip last one if file doesn't exist — it will be created.)*

### 4. Install and enable the systemd service

```bash
sudo ./nsagent.py --service
sudo systemctl daemon-reload
sudo systemctl restart nodesniff-agent
sudo systemctl enable nodesniff-agent
```

Agent will now run as `nodesniff` user.

### 5. Confirm it's working

```bash
ps aux | grep nsagent
systemctl status nodesniff-agent
```

You should see `User=nodesniff`.

---

## CLI Modes

- `sudo ./nsagent.py`  
  One-time run (registers if needed, then loops)

- `sudo ./nsagent.py --service`  
  Installs systemd service (requires registration)

- `sudo ./nsagent.py --clean`  
  Uninstalls: removes configs, service, logs, symlink

---

## Re-registration (after dashboard deletion)

```bash
sudo ./nsagent.py
# Paste company key again if prompted
sudo ./nsagent.py --service
```

---

## Updating the Agent

```bash
sudo ./nsagent.py --clean
# Copy updated nsagent.py
sudo ./nsagent.py
sudo ./nsagent.py --service
```

---

## Uninstall

```bash
sudo ./nsagent.py --clean
```

---

## License

GPL v3 — **non-commercial use only**.  
For commercial use or support, contact us: [info@nodesniff.com](mailto:info@nodesniff.com)

---

## Contact

📧 info@nodesniff.com  
🌐 https://www.nodesniff.com