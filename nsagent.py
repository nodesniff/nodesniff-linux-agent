#!/usr/bin/env python3
# ------------------------------------------------------------------------------
# NodeSniff Agent - Lightweight Linux metrics collector
#
# Author: Sebastian Zieba <www.zieba.art>
# License: GNU GPL v3 (non-commercial use only)
#
# This software is licensed under the terms of the GNU General Public License
# version 3 (GPLv3) as published by the Free Software Foundation, for
# non-commercial use only.
#
# Special CLI modes:
#   --service  - install agent as a systemd service (requires existing/valid config+token)
#   --clean    - full cleanup: removes service, config, logs, metrics and dev dirs (safe to call repeatedly)
# ------------------------------------------------------------------------------

AGENT_VERSION = "1.1.1"

import os, sys, json, time, yaml, uuid, hmac, psutil, socket, hashlib, logging, requests, platform, subprocess, shutil
from pathlib import Path
import importlib.util
from multiprocessing import Process, Queue

CONFIG_DIR = "/etc/nodesniff"
CONFIG_PATH = os.path.join(CONFIG_DIR, "nsconfig.yaml")
TOKEN_PATH = os.path.join(CONFIG_DIR, "nsagent.token")
METRICS_PATH = Path("/usr/lib/nodesniff/metrics")
AGENT_DEST_PATH = "/usr/lib/nodesniff/nsagent.py"
SERVICE_PATH = "/etc/systemd/system/nodesniff-agent.service"
LOG_PATH = "/var/log/nsagent.log"
AGENT_BIN_LINK = "/usr/bin/nsagent"

def print_info(msg):
    """Prints an informational message in cyan color."""
    print(f"\033[96m[INFO]\033[0m {msg}")

def print_ok(msg):
    """Prints a success message in green color."""
    print(f"\033[92m[OK]\033[0m {msg}")

def print_error(msg):
    """Prints an error message in red color."""
    print(f"\033[91m[ERROR]\033[0m {msg}")

import hashlib

def get_machine_id():
    """
    Returns the machine unique identifier (from /etc/machine-id).
    If not available, generates a random UUID (for test/dev only).
    """
    try:
        with open("/etc/machine-id", "r") as f:
            return f.read().strip()
    except Exception:
        return str(uuid.uuid4())  # fallback: losowy (dla testów)

def setup_logger(level_str="INFO"):
    """
    Sets up logging for both stdout (with colors) and to file (plain).
    """
    class ColorFormatter(logging.Formatter):
        COLORS = {
            'DEBUG': "\033[37m",    # White
            'INFO': "\033[96m",     # Cyan
            'WARNING': "\033[93m",  # Yellow
            'ERROR': "\033[91m",    # Red
            'CRITICAL': "\033[95m"  # Magenta
        }
        RESET = "\033[0m"
        def format(self, record):
            color = self.COLORS.get(record.levelname, "")
            msg = logging.Formatter.format(self, record)
            return f"{color}{msg}{self.RESET}"
    handler1 = logging.StreamHandler(sys.stdout)
    handler1.setFormatter(ColorFormatter("%(asctime)s [%(levelname)s] %(message)s"))
    handler2 = logging.FileHandler(LOG_PATH)
    handler2.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logging.basicConfig(level=getattr(logging, level_str.upper(), logging.INFO),
                        handlers=[handler1, handler2])

def get_hardware_id():
    """
    Returns a persistent hardware identifier for the host.
    Falls back to random UUID on error.
    """
    try:
        with open("/etc/machine-id", "r") as f:
            return f.read().strip()
    except Exception as e:
        logging.warning(f"Unable to read machine-id: {e}")
        return str(uuid.uuid4())

def get_domain_name():
    """
    Attempts to determine the domain name of the host.
    Checks /etc/resolv.conf and hostname -d output.
    Returns empty string if not found.
    """
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("search"):
                    parts = line.strip().split()
                    if len(parts) > 1 and parts[1] != ".":
                        return parts[1]
        domain = subprocess.check_output("hostname -d", shell=True).decode().strip()
        if domain and domain != "(none)":
            return domain
    except Exception as e:
        logging.warning(f"Cannot determine domain_name: {e}")
    return ""

def ensure_files():
    """
    Ensures that all required agent files and directories exist.
    Copies agent code and metric plugins if missing.
    Creates config and token placeholders if necessary.
    """
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(METRICS_PATH, exist_ok=True)
    if not os.path.exists(AGENT_DEST_PATH):
        try:
            shutil.copy2(__file__, AGENT_DEST_PATH)
            logging.info(f"Copied agent to {AGENT_DEST_PATH}")
        except Exception as e:
            logging.warning(f"Could not copy agent to {AGENT_DEST_PATH}: {e}")
    local_metrics_path = Path(__file__).parent / "metrics"
    if local_metrics_path.exists():
        for src in local_metrics_path.glob("*.py"):
            dst = METRICS_PATH / src.name
            try:
                shutil.copy2(src, dst)
                logging.info(f"Copied metric {src.name} to {dst}")
            except Exception as e:
                logging.warning(f"Failed to copy metric {src.name}: {e}")
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            yaml.dump({
                "api_url": "https://nodesniff.com/api",
                "interval_seconds": 60,
                "log_level": "INFO",
                "hardware_id": get_hardware_id()
            }, f)
        print_info(f"Created default config: {CONFIG_PATH}")
    if not os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH, "w") as f:
            f.write("<<<PASTE_YOUR_TOKEN>>>\n")
        print_info(f"Created token placeholder: {TOKEN_PATH}")

def load_config():
    """
    Loads the agent configuration from the YAML config file.
    """
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)

def save_config(cfg):
    """
    Saves the agent configuration to the YAML config file.
    """
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(cfg, f)

def load_company_key():
    """
    Loads the company key (token) from the token file.
    Exits the agent if missing or placeholder is present.
    """
    if not os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH, "w") as f:
            f.write("<<<PASTE_YOUR_TOKEN>>>\n")
        print_info(f"Created token placeholder: {TOKEN_PATH}")
    with open(TOKEN_PATH) as f:
        key = f.read().strip()
        if not key or "<<<" in key:
            print_error("TOKEN not set. Please paste it into /etc/nodesniff/nsagent.token.")
            logging.error("Agent will not start without a valid TOKEN.")
            sys.exit(1)
        return key

def register_agent(cfg, company_key):
    """
    Registers the agent on the backend using the company key.
    Saves api_token, hmac_secret and machine_id to config on success.
    """
    url = cfg["api_url"].rstrip("/") + "/register"
    hostname = platform.node()
    hardware_id = cfg["hardware_id"]
    headers = {
        "X-Company-Key": company_key,
        "Content-Type": "application/json"
    }
    payload = {
        "name": hostname,
        "hostname": hostname,
        "hardware_id": hardware_id
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=10)
        if r.status_code == 200:
            result = r.json()
            cfg["api_token"] = result["api_token"]
            cfg["hmac_secret"] = result["hmac_secret"]
            cfg["machine_id"] = get_machine_id()
            save_config(cfg)
            print_ok("Registration successful.")
            logging.info("Registration successful.")
        else:
            logging.error(f"Registration failed: {r.status_code} {r.text}")
            sys.exit(1)
    except Exception as e:
        logging.exception("Registration exception")
        sys.exit(1)

def fetch_plugin_hashes_from_api(cfg):
    """
    Fetches the trusted hashes for plugins from the backend API.
    Returns a dictionary of plugin hashes or an empty dict on failure.
    """
    try:
        headers = {"Authorization": f"Bearer {cfg['api_token']}"}
        url = cfg["api_url"].rstrip("/") + "/plugin-hashes"
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            return r.json()
        else:
            logging.warning(f"Could not fetch plugin hashes: {r.status_code}")
    except Exception as e:
        logging.warning(f"Hash API fetch failed: {e}")
    return {}

def run_plugin(path: Path, q: Queue):
    """
    Executes a given plugin Python file securely in a subprocess and returns the results via a queue.
    """
    try:
        spec = importlib.util.spec_from_file_location("plugin", str(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, "get"):
            result = module.get()
            if isinstance(result, dict):
                q.put(result)
    except Exception as e:
        q.put({"error": str(e)})

def agent_exists_on_backend(api_url, hardware_id, api_token):
    """
    Checks if agent with given hardware_id exists on backend using the dedicated /exists endpoint.
    Returns True if agent exists, False otherwise.
    """
    url = f"{api_url.rstrip('/')}/server/{hardware_id}/exists"
    headers = {"Authorization": f"Bearer {api_token}"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get("exists", False) is True
        else:
            # Not found, deleted, or error
            return False
    except Exception as e:
        print_error(f"Error checking agent existence: {e}")
        return False

def install_service():
    """
    Installs the agent as a systemd service ONLY if agent is registered and exists on backend.
    Double-checks agent existence before and after file/config verification.
    No registration, no config modification, no metric sending.
    """
    # 1. FIRST: check agent existence on backend
    # (use whatever config is on disk, or ask user to fix it)
    if not os.path.exists(CONFIG_PATH):
        print_error("Agent is not registered (missing config). Run agent manually first to register.")
        sys.exit(1)
    try:
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f)
        api_token = cfg.get("api_token")
        hardware_id = cfg.get("hardware_id")
        api_url = cfg.get("api_url", "https://nodesniff.com/api")
        if not api_token or not hardware_id:
            print_error("Agent config incomplete: missing token or hardware_id.")
            sys.exit(1)
    except Exception as e:
        print_error(f"Config read failed: {e}")
        sys.exit(1)

    print_info(f"[Step 1] Checking if agent [{hardware_id}] exists on NodeSniff backend via /exists endpoint...")
    if not agent_exists_on_backend(api_url, hardware_id, api_token):
        print_error("Agent does NOT exist or is deleted on backend. Service will NOT be installed.")
        sys.exit(1)
    print_ok("Agent exists on backend. Proceeding with local config check...")

    # 2. Double-check all required local config fields (can be redundant, but ensures robustness)
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f)
    hmac_secret = cfg.get("hmac_secret")
    if not api_token or not hmac_secret or not hardware_id:
        print_error("Agent config incomplete: missing token, hmac_secret, or hardware_id.")
        sys.exit(1)

    # 3. FINAL CHECK: agent existence on backend (handles possible race/caching)
    print_info(f"[Step 2] Final check if agent [{hardware_id}] still exists in backend...")
    if not agent_exists_on_backend(api_url, hardware_id, api_token):
        print_error("Agent disappeared from backend during setup. Aborting installation.")
        sys.exit(1)
    print_ok("Agent exists and is active on backend. Proceeding to install systemd service...")

    # 4. Install systemd service
    script_path = os.path.abspath(__file__)
    os.makedirs("/usr/lib/nodesniff", exist_ok=True)
    shutil.copy2(script_path, AGENT_DEST_PATH)
    print_ok(f"Copied agent to {AGENT_DEST_PATH}")

    # Create or update symlink in /usr/bin
    if os.path.islink(AGENT_BIN_LINK) or os.path.exists(AGENT_BIN_LINK):
        os.remove(AGENT_BIN_LINK)
    os.symlink(AGENT_DEST_PATH, AGENT_BIN_LINK)
    os.chmod(AGENT_BIN_LINK, 0o755)
    print_ok(f"Symlink created at {AGENT_BIN_LINK} -> {AGENT_DEST_PATH}")

    # Write systemd service file
    service_unit = f"""[Unit]
Description=NodeSniff Metrics Agent
After=network.target

[Service]
Type=simple
User=nodesniff
Group=nodesniff
ExecStart=/usr/bin/python3 {AGENT_DEST_PATH}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    with open(SERVICE_PATH, "w") as f:
        f.write(service_unit)
    print_ok(f"Systemd service file created at {SERVICE_PATH}")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "nodesniff-agent"], check=True)
    subprocess.run(["systemctl", "restart", "nodesniff-agent"], check=True)
    print_ok("NodeSniff agent installed and started as systemd service.")

def collect_metrics(cfg):
    """
    Collects various system metrics including CPU, memory, disk usage, network IO, and temperature.
    Incorporates additional metrics from trusted plugins, ensuring they match known hashes.
    """
    vmem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    cpu_freq = psutil.cpu_freq()
    load_avg = os.getloadavg()
    boot_time = int(psutil.boot_time())
    users = len(psutil.users())
    hardware_id = cfg["hardware_id"]
    disk = psutil.disk_usage('/')
    disk_io = psutil.disk_io_counters()
    net = psutil.net_io_counters()

    try:
        temps = psutil.sensors_temperatures()
        cpu_temp = next((round(entry.current, 1) for entries in temps.values() for entry in entries if entry.current), None)
    except:
        cpu_temp = None

    internal_ip = next((a.address for iface in psutil.net_if_addrs().values()
                        for a in iface if a.family == socket.AF_INET and a.address != "127.0.0.1"), "Brak")

    try:
        server_ip = requests.get("https://api.ipify.org", timeout=5).text
    except:
        server_ip = internal_ip

    try:
        gateway = subprocess.check_output("ip route | grep default", shell=True).decode().split()[2]
    except:
        gateway = "No Gateway"

    try:
        with open("/etc/resolv.conf") as f:
            dns = ", ".join(line.split()[1] for line in f if line.startswith("nameserver"))
    except:
        dns = "No DNS"

    domain_name = get_domain_name()
    extra_metrics = {}
    trusted_plugins = fetch_plugin_hashes_from_api(cfg)

    if METRICS_PATH.exists() and trusted_plugins:
        for py_file in METRICS_PATH.glob("*.py"):
            expected_hash = trusted_plugins.get(py_file.name)
            if not expected_hash:
                continue
            try:
                with open(py_file, "rb") as f:
                    local_hash = hashlib.sha256(f.read()).hexdigest()
                if local_hash != expected_hash:
                    logging.warning(f"Plugin {py_file.name} hash mismatch. Skipping.")
                    continue

                q = Queue()
                p = Process(target=run_plugin, args=(py_file, q))
                p.start()
                p.join(timeout=2)

                if p.is_alive():
                    p.terminate()
                    logging.warning(f"Plugin {py_file.name} timeout.")
                    continue

                if not q.empty():
                    result = q.get()
                    if isinstance(result, dict):
                        extra_metrics.update(result)
            except Exception as e:
                logging.warning(f"Plugin error {py_file.name}: {e}")
    return {
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory_usage": vmem.percent,
        "load_avg_1min": load_avg[0],
        "load_avg_5min": load_avg[1],
        "load_avg_15min": load_avg[2],
        "process_count": len(psutil.pids()),
        "disk_usage": disk.percent,
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "internal_ip": internal_ip,
        "server_ip": server_ip,
        "gateway": gateway,
        "dns": dns,
        "uptime": int(time.time() - boot_time),
        "domain_name": domain_name,
        "hostname": platform.node(),
        "os_name": platform.system(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "agent_version": AGENT_VERSION,
        "cpu_cores_physical": psutil.cpu_count(logical=False),
        "cpu_cores_logical": psutil.cpu_count(logical=True),
        "cpu_freq_current": int(cpu_freq.current) if cpu_freq else None,
        "cpu_freq_max": int(cpu_freq.max) if cpu_freq else None,
        "cpu_temp": cpu_temp,
        "memory_total_mb": int(vmem.total / 1024 / 1024),
        "memory_used_mb": int(vmem.used / 1024 / 1024),
        "memory_cached_mb": int(getattr(vmem, "cached", 0) / 1024 / 1024),
        "swap_total_mb": int(swap.total / 1024 / 1024),
        "swap_used_mb": int(swap.used / 1024 / 1024),
        "disk_io_read_bytes": disk_io.read_bytes if disk_io else 0,
        "disk_io_write_bytes": disk_io.write_bytes if disk_io else 0,
        "disk_io_read_count": disk_io.read_count if disk_io else 0,
        "disk_io_write_count": disk_io.write_count if disk_io else 0,
        "users_logged_in": users,
        "boot_time_epoch": boot_time,
        "net_bytes_sent": net.bytes_sent if net else 0,
        "net_bytes_recv": net.bytes_recv if net else 0,
        "cloud_provider": None,
        "cloud_instance_id": None,
        "cloud_region": None,
        "hardware_id": hardware_id,
        "extra_metrics": extra_metrics,
         "timestamp": int(time.time())
    }

def send_metrics(cfg, metrics):
    """
    Sends collected metrics securely to the backend API.
    Metrics are signed with HMAC to verify authenticity.
    Handles specific HTTP responses including token invalidation.
    """
    payload = json.dumps(metrics).encode()
    signature = hmac.new(cfg["hmac_secret"].encode(), payload, hashlib.sha256).hexdigest()
    headers = {
        "Authorization": f"Bearer {cfg['api_token']}",
        "X-Signature": signature,
        "Content-Type": "application/json"
    }
    try:
        url = cfg["api_url"].rstrip("/") + "/report"
        r = requests.post(url, headers=headers, data=payload, timeout=10)
        if r.status_code == 200:
            print_ok("📤 Metrics sent successfully.")
            logging.info("📤 Metrics sent successfully.")
        elif r.status_code == 403:
            print_error("❌ Agent was removed via UI or token is invalid (HTTP 403).")
            print_error("You must re-register this agent to continue monitoring.")
            # Remove config & token to force re-registration
            if os.path.exists(CONFIG_PATH): os.remove(CONFIG_PATH)
            if os.path.exists(TOKEN_PATH): os.remove(TOKEN_PATH)
            print_info("Agent config and token removed, registration required on next start.")
            sys.exit(1)
        else:
            logging.error(f"Send failed: {r.status_code} {r.text}")
    except Exception as e:
        logging.exception("Error sending metrics")

def clean_agent():
    """
    Full cleanup: removes service, config, logs, metrics and dev dirs, and symlink. Safe to call repeatedly.
    """
    print_info("Stopping and disabling systemd service...")
    subprocess.run(["systemctl", "stop", "nodesniff-agent"], stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "disable", "nodesniff-agent"], stderr=subprocess.DEVNULL)
    if os.path.exists(SERVICE_PATH):
        os.remove(SERVICE_PATH)
        print_ok(f"Removed {SERVICE_PATH}")
    subprocess.run(["systemctl", "daemon-reload"], stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "reset-failed"], stderr=subprocess.DEVNULL)
    print_ok("Systemd service cleaned up.")
    
    print_info("Removing config and token files...")
    if os.path.isdir(CONFIG_DIR):
        shutil.rmtree(CONFIG_DIR, ignore_errors=True)
        print_ok(f"Removed {CONFIG_DIR}")
    else:
        print_ok(f"No {CONFIG_DIR} to remove.")

    print_info("Removing log file...")
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)
        print_ok(f"Removed {LOG_PATH}")
    else:
        print_ok("No log file found.")

    print_info("Removing extra metrics directory...")
    if METRICS_PATH.exists():
        shutil.rmtree(METRICS_PATH, ignore_errors=True)
        print_ok(f"Removed {METRICS_PATH}")

    try:
        os.rmdir("/usr/lib/nodesniff")
        print_ok("Removed /usr/lib/nodesniff (parent dir empty)")
    except Exception:
        pass

    print_info("Removing local dev/test directories (if exist)...")
    for d in ["./nodesniff_test", "./nodesniff_clean", "./nodesniff_autoreg_fixed"]:
        shutil.rmtree(d, ignore_errors=True)
        print_ok(f"Removed {d}")

    # Remove /usr/bin/nsagent symlink if exists
    if os.path.islink(AGENT_BIN_LINK) or os.path.exists(AGENT_BIN_LINK):
        os.remove(AGENT_BIN_LINK)
        print_ok(f"Removed symlink {AGENT_BIN_LINK}")
    else:
        print_ok(f"No symlink {AGENT_BIN_LINK} to remove.")

    print("\033[95m[DONE]\033[0m NodeSniff cleanup complete.")

# --- CLI entrypoint ---
if __name__ == "__main__":
    """
    Command Line Interface (CLI) entrypoint.
    Supports '--clean' for cleanup and '--service' for systemd service installation.
    Handles agent registration and metrics reporting.
    """
    if "--clean" in sys.argv:
        clean_agent()
        sys.exit(0)
    if "--service" in sys.argv:
        install_service()
        sys.exit(0)

    setup_logger("INFO")
    ensure_files()
    cfg = load_config()

    # Register the agent if not registered yet
    if "api_token" not in cfg or "hmac_secret" not in cfg:
        key = load_company_key()
        register_agent(cfg, key)
        metrics = collect_metrics(cfg)
        send_metrics(cfg, metrics)
        print_ok("Registration complete. You can now start nsagent in background with '&' (./nsagent.py &) or use '--service' to install as a systemd service.")
        sys.exit(0)

    # Check if machine-id in config matches the current host
    config_machine_id = cfg.get("machine_id")
    actual_machine_id = get_machine_id()
    if not config_machine_id or not actual_machine_id:
        print_error("Missing machine-id in config or system!")
        sys.exit(1)
    if config_machine_id != actual_machine_id:
        print_error("Agent config was copied from another host (machine-id mismatch). Registration required!")
        sys.exit(1)

    # Main metrics loop
    interval = max(cfg.get("interval_seconds", 60), 10)
    while True:
        metrics = collect_metrics(cfg)
        send_metrics(cfg, metrics)
        time.sleep(interval)


