# ------------------------------------------------------------------------------
# NodeSniff Agent - Lightweight Linux metrics collector
#
# Author: Sebastian Zieba <sebastian@zieba.art>
# License: GNU GPL v3 (non-commercial use only)
#
# This software is licensed under the terms of the GNU General Public License
# version 3 (GPLv3) as published by the Free Software Foundation, **for
# non-commercial use only**.
#
# For commercial licensing, please contact the author directly.
# ------------------------------------------------------------------------------

import psutil
import time

def get():
    try:
        # Priming: For accurate CPU usage, call cpu_percent(interval=None) on all processes first.
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(interval=None)
            except Exception:
                continue  # Ignore processes that no longer exist

        # Short delay to allow psutil to calculate CPU percent over an interval
        time.sleep(0.1)

        processes = []
        # Gather process info including CPU percent and memory usage
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
            try:
                info = proc.info
                memory_rss = info.get('memory_info').rss if info.get('memory_info') else 0
                processes.append({
                    "pid": info['pid'],                             # Process ID
                    "name": info['name'] or "unknown",              # Process name (fallback if None)
                    "cpu": round(info['cpu_percent'], 1),           # CPU usage in percent
                    "ram": round(memory_rss / 1024 / 1024, 1)       # RAM usage in MB (RSS)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue  # Skip processes that are gone or inaccessible

        # Sort processes by CPU usage descending and return top 10
        top = sorted(processes, key=lambda p: p['cpu'], reverse=True)[:10]
        return {"top_cpu_processes": top}

    except Exception as e:
        # If anything goes wrong, return error string in result
        return {"top_cpu_processes": f"Error: {str(e)}"}

