# ------------------------------------------------------------------------------
# NodeSniff Agent - top 10 CPU-consuming processes (non-blocking, cached)
#
# Author: Sebastian Zieba <sebastian@zieba.art>
# License: GNU GPL v3 (non-commercial use only)
# Version: 1.1.1
# Date: 2025-06-27
# ------------------------------------------------------------------------------

import psutil
import threading
import time

_cached_processes = []
_last_update = 0
_update_interval = 30  # seconds
_first_run = True  # one-time blocking priming

def _update_cache():
    global _cached_processes, _last_update

    processes = []
    try:
        primed = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc.cpu_percent(interval=None)
                primed.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(1.0)  # wait to measure actual CPU usage

        for proc in primed:
            try:
                info = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_info'])
                memory_rss = info['memory_info'].rss if info['memory_info'] else 0
                processes.append({
                    "pid": info['pid'],
                    "name": info['name'] or "unknown",
                    "cpu": round(info['cpu_percent'], 1),
                    "ram": round(memory_rss / 1024 / 1024, 1)  # MB
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        _cached_processes = sorted(processes, key=lambda p: (p['cpu'], p['ram']), reverse=True)[:10]
        _last_update = time.time()

    except Exception:
        _cached_processes = []
        _last_update = time.time()

def get():
    global _last_update, _first_run

    now = time.time()

    if _first_run:
        _update_cache()  # blocking on first call to fill cache
        _first_run = False
    elif now - _last_update > _update_interval:
        threading.Thread(target=_update_cache, daemon=True).start()

    return {"top_cpu_processes": _cached_processes}

# Optional debug entry point
if __name__ == "__main__":
    import json
    print(json.dumps(get(), indent=2))