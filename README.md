# RansomBPF: eBPF-Based Ransomware Prevention System

![Version](https://img.shields.io/badge/version-v0.9.0-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20eBPF-orange)
![License](https://img.shields.io/badge/license-GPL-green)
![Type](https://img.shields.io/badge/type-Graduation%20Project-red)

> **RansomBPF** is a next-generation security tool designed to detect and stop ransomware attacks on Linux systems in real-time. Unlike traditional signature-based antiviruses, it uses **eBPF (Extended Berkeley Packet Filter)** technology to monitor kernel-level behavioral patterns and neutralizes threats in **under 100ms**.

---

##  Table of Contents
- [Key Features](#key--features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation & Build](#installation--build)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing & Simulation](#testing--simulation)
- [Logging & Forensics](#logging--forensics)
- [License](#license)

---

##  Key Features

### 1. Active Defense (IPS Mode)
* **Kill Switch:** Automatically terminates processes that exceed the risk threshold (`RISK_THRESHOLD=100`).
* **Safety Filters:** Built-in protection for critical system processes (PID 0/1) to prevent system instability.

### 2. Universal Coverage
* **Polyglot Detection:** Detects ransomware written in **C/C++** (`write`, `rename`), **Python/Java** (`pwrite64`), and **Go/NodeJS** (`writev`).
* **Atomic Operations:** Monitors modern file system calls like `renameat2` used by sophisticated malware.

### 3. Context-Aware Heuristics
* **Extension Penalty:** Applies penalty scores for suspicious extension changes (e.g., `.locked`, `.enc`).
* **Directory Sensitivity:** Assigns higher risk multipliers to critical paths (`/etc`, `/home`) and lower multipliers to noisy paths (`/tmp`).
* **Time Decay:** Implements a decay algorithm to mitigate "Low and Slow" attacks by reducing risk scores over time.

### 4. Operational Stability
* **O(1) Whitelisting:** Uses a high-performance hash table to filter trusted processes (e.g., `systemd`, `git`, `apt`) with zero latency.
* **Self-Monitoring:** Intelligent PID filtering prevents the agent from analyzing its own logs, avoiding feedback loops.

---

##  Architecture

RansomBPF operates on a hybrid architecture:

1.  **Kernel Space (Data Collector):**
    * Lightweight eBPF programs hook into tracepoints (`sys_enter_write`, `sys_enter_renameat2`, etc.).
    * Collects metadata: PID, UID, PPID, Comm, Filename.
    * Sends events to user space via a high-performance **Ring Buffer**.

2.  **User Space (Analysis Engine):**
    * **State Manager:** Tracks per-process statistics using `uthash`.
    * **Heuristic Engine:** Calculates risk scores based on event weights and context.
    * **Response Module:** Triggers alarms or sends `SIGKILL` signals.
    * **Logger:** Writes structured JSON logs for SIEM integration.

---

##  Prerequisites

Ensure your system meets the following requirements:
* **OS:** Linux (Kernel v5.8+ recommended for full BTF/CO-RE support).
* **Privileges:** Root access (required for loading eBPF programs).

Install build dependencies (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install clang llvm libbpf-dev make gcc cmake git bpftool linux-headers-$(uname -r)
```

---

##  Installation & Build

### 1. Clone the Repository
```bash
git clone [https://github.com/osmancevik/ransom-bpf.git](https://github.com/osmancevik/ransom-bpf.git)
cd ransom-bpf
```

### 2. Generate Kernel Headers (Crucial)
RansomBPF uses CO-RE (Compile Once – Run Everywhere). You must generate the `vmlinux.h` file matching your running kernel:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### 3. Build the Project
Use CMake to compile the eBPF kernel object and the user-space agent:
```bash
mkdir build && cd build
cmake ..
make
```

### 4. Install System-Wide
Installs the binary, configuration, and systemd service:
```bash
sudo make install
```
* Binary: `/usr/local/bin/ransom_bpf`
* Config: `/etc/ransom-bpf/ransom.conf`
* Service: `ransom-bpf.service`

---

##  Configuration

The behavior of the agent is controlled via `/etc/ransom-bpf/ransom.conf`.
Key parameters:

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `ACTIVE_BLOCKING` | `true` | Enable/Disable automatic process termination (IPS mode). |
| `RISK_THRESHOLD` | `100` | Cumulative score required to trigger an alarm/action. |
| `SCORE_WRITE` | `2` | Points added per file write operation. |
| `SCORE_RENAME` | `20` | Points added per file rename operation. |
| `SCORE_HONEYPOT` | `1000` | Points added for touching the honeypot file. |
| `WHITELIST` | `systemd...` | Comma-separated list of trusted processes. |

---

##  Usage

### Running as a Service (Recommended)
```bash
sudo systemctl start ransom-bpf
sudo systemctl status ransom-bpf
# To view logs:
sudo tail -f /var/log/ransom-bpf/service.log
```

### Manual Execution (Debugging)
```bash
# Run with default config
sudo ransom_bpf

# Run with custom config
sudo ransom_bpf -c ./ransom.conf

# Show version
ransom_bpf --version
```

---

##  Testing & Simulation

The project includes a **Live Fire** simulation suite to validate detection rules safely.

1.  **Setup Victim Environment:**
    Creates dummy files and a honeypot in `/home/developer/test_files`.
    ```bash
    ./setup_victim.sh
    ```

2.  **Run Ransomware Simulator:**
    Mimics a real attack (encryption, extension change, ransom note).
    ```bash
    python3 ransom_simulator.py
    ```

**Expected Result:**
* The agent detects the attack within milliseconds.
* The `python3` process is killed immediately.
* A `PROCESS_KILLED` alert is logged.

---

##  Logging & Forensics

RansomBPF provides multi-channel logging for SOC/SIEM integration:

1.  **Service Log (`service.log`):** Human-readable operational logs.
2.  **Alert Log (`alerts.json`):** High-fidelity security alerts.
    ```json
    {
      "timestamp": "2026-01-04 14:00:01.123",
      "level": "ALARM",
      "alert_type": "PROCESS_KILLED",
      "pid": 4120,
      "ppid": 3890,
      "uid": 1000,
      "comm": "python3",
      "filename": "/home/user/doc.docx.locked",
      "risk_reason": "SUSPICIOUS EXTENSION",
      "score": 142
    }
    ```
3.  **Audit Log (`audit.json`):** Raw stream of file system events (optional).

---

## Acknowledgments
This project was developed under the supervision of **Dr. Hasan Yetis**
- [View Academic Profile]([https://scholar.google.com/citations?user=Nwp3Q0oAAAAJ&hl=tr])

##  License

This project is licensed under the **GPL-2.0 License** - see the [LICENSE]() file for details.

**Author:** Osman Cevik  
**Project:** Computer Engineering Graduation Project