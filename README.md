# NodeSniff Agent

NodeSniff Agent is a lightweight server metrics collector for the NodeSniff monitoring system.  
The agent collects and securely sends metrics to your NodeSniff backend over HTTPS.

**License:** GNU GPL v3 (non-commercial use only)

---

## Features

- Collects CPU, RAM, disk, network, and OS metrics (extensible via Python plugins)
- Secure HTTPS metric transmission with HMAC authentication
- CLI modes for install, remove, cleanup
- Systemd integration with `/usr/bin/nsagent` symlink for convenience

---

## Requirements

- Python 3.7+
- Linux (x86, ARM, etc.)
- Python packages:
  - `psutil`, `PyYAML`, `requests`

Install dependencies:
```sh
pip install -r requirements.txt
```

---

## Installation

1. **Copy the agent to your server:**
   ```sh
   scp nsagent.py user@your-server:/path/
   ```

2. **Run the agent for initial setup:**
   ```sh
   sudo python3 ./nsagent.py
   ```

   - Creates `/etc/nodesniff/` with placeholder config and token.
   - Paste your company key into `/etc/nodesniff/nsagent.token`.
   - Re-run the agent:
     ```sh
     sudo ./nsagent.py
     ```

   - Expected output:
     ```
     [OK] Registration successful.
     [OK] 📤 Metrics sent successfully.
     ```

3. **Install as a systemd service:**
   ```sh
   sudo ./nsagent.py --service
   ```

   - Requires a successful registration.
   - Installs `nodesniff-agent` systemd service and enables it on boot.
   - Adds `/usr/bin/nsagent` CLI symlink.

---

## CLI Modes

- `sudo ./nsagent.py`  
  Standard agent run. Registers (if needed) and enters metric loop.

- `sudo ./nsagent.py --service`  
  Installs as a systemd service (requires registration).

- `sudo ./nsagent.py --clean`  
  Full cleanup:
  - Stops and disables service
  - Removes config, token, logs, metrics
  - Deletes `/usr/bin/nsagent` symlink

---

## Re-registration (after removal in dashboard)

If the server is deleted from the NodeSniff dashboard, the agent will detect this (`403 Forbidden`).  
To re-register:

1. Run:
   ```sh
   sudo ./nsagent.py
   ```

2. Re-paste your company key if prompted.

3. Re-install the service:
   ```sh
   sudo ./nsagent.py --service
   ```

---

## Updating the Agent

After downloading a new version:

```sh
sudo ./nsagent.py --clean
# Copy updated nsagent.py
sudo python3 ./nsagent.py
sudo ./nsagent.py --service
```

---

## Uninstall

```sh
sudo ./nsagent.py --clean
```

Completely removes the agent: service, configs, logs, symlink.

---

## License

GPL v3 — **non-commercial use only**.  
For commercial use or support, contact us at [info@nodesniff.com](mailto:info@nodesniff.com).

---

## Contact

📧 info@nodesniff.com  
🌐 https://www.nodesniff.com
