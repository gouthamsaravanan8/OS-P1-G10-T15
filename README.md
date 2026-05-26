Markdown
# Group 10 — Project 15: USB File Transfer Activity Driver

This project implements a **Linux kernel module driver** that monitors file transfer activity to removable USB storage devices, paired with a **user-space C application** for real-time logging, statistics, and anomaly detection.  It is designed for **data loss prevention (DLP)**, **cybersecurity auditing**, and **secure storage** use cases on the **Raspberry Pi 4 (Raspbian 64-bit)**.

---

## Table of Contents

1. [Directory Structure](#directory-structure)
2. [Prerequisites](#prerequisites)
3. [Quick Start (Automated)](#quick-start-automated)
4. [Manual Build & Execution](#manual-build--execution)
5. [User-Space Application Usage](#user-space-application-usage)
6. [Verifying Kernel Logging](#verifying-kernel-logging)
7. [Demonstration Checklist](#demonstration-checklist)
8. [Troubleshooting](#troubleshooting)
9. [Submission Deliverables](#submission-deliverables)

---

## Directory Structure

```text
OS-Grp-10/
├── .gitignore                  # Build exclusion configurations
├── README.md                   # This file — full documentation
├── Makefile                    # Top-level build orchestration
│
├── include/
│   └── usb_tracker.h           # Shared header: ioctl commands, data structs
│
├── src_kernel/                 # Linux Kernel Module (LKM)
│   ├── Makefile                # Kbuild script for module compilation
│   └── usb_audit.c             # Character device driver + USB notifier
│
├── src_user/                   # User-space applications
│   ├── usb_monitor.c           # C monitor app (interactive + daemon mode)
│   └── file_tracker.py         # Python watchdog daemon (alternative monitor)
│
└── scripts/
    └── run.sh                  # Bash automation: build → load → run → cleanup
```

---

## Prerequisites

The system must be compiled and executed on a **Raspberry Pi 4 running Raspbian 64-bit**.

### 1. Install Kernel Headers & Build Essentials

```bash
sudo apt update
sudo apt install raspberrypi-kernel-headers build-essential -y
```

### 2. Install Python Dependencies (for Python user-space app)

```bash
sudo apt install python3-watchdog -y
```

### 3. Verify USB Storage Device

Plug in your target USB thumb drive and note its mount point:

```bash
lsblk
# Look for the MOUNTPOINT column — e.g. /media/pi/SAMSUNG
```

> **Important:** Update `USB_TARGET_PATH` in `src_user/file_tracker.py` to match your USB mount point.

---

## Quick Start (Automated)

The `scripts/run.sh` Bash script automates the full lifecycle:

| Step | Action |
|------|--------|
| 1 | Checks for root privileges & kernel headers |
| 2 | Compiles the kernel module (`usb_audit.ko`) |
| 3 | Compiles the user-space C application (`usb_monitor`) |
| 4 | Loads the kernel module with `insmod` |
| 5 | Verifies `/dev/usb_audit` device node creation |
| 6 | Prints recent `dmesg` kernel logs |
| 7 | Launches the interactive monitor |
| 8 | On exit, unloads the module (`rmmod`) and cleans up |

```bash
chmod +x scripts/run.sh
sudo ./scripts/run.sh --interactive
```

For daemon (dashboard refresh) mode:

```bash
sudo ./scripts/run.sh --daemon
```

---

## Manual Build & Execution

### Step 1: Build Everything

```bash
# From the project root:
make all
```

This compiles both the kernel module and the user-space application.

Alternatively, build individually:

```bash
make kernel    # builds src_kernel/usb_audit.ko
make user      # builds src_user/usb_monitor
```

### Step 2: Load the Kernel Module

```bash
sudo insmod src_kernel/usb_audit.ko
```

Verify the module loaded and the device node was created:

```bash
lsmod | grep usb_audit
ls -la /dev/usb_audit
```

### Step 3: Run the User-Space C Application

```bash
sudo ./src_user/usb_monitor --interactive
```

Or use the Python watchdog daemon as an alternative:

```bash
python3 src_user/file_tracker.py
```

### Step 4: Unload the Kernel Module (Clean Shutdown)

```bash
sudo rmmod usb_audit
```

### Step 5: Clean Build Artifacts

```bash
make clean
```

---

## User-Space Application Usage

### C Application (`usb_monitor`)

The C application communicates with the kernel driver through the `/dev/usb_audit` character device using **ioctl** system calls.

```
Usage: ./usb_monitor [OPTION]

Options:
  -i, --interactive      Interactive test menu (default)
  -d, --daemon           Periodic dashboard refresh mode
  -p, --path <path>      Set monitored USB mount path
  -t, --threshold <n>    Anomaly: max file ops before alert (default: 5)
  -w, --window <ms>      Anomaly: sliding time window in ms (default: 3000)
  -h, --help             Show this help message
```

#### Interactive Mode Commands

| Command | Description |
|---------|-------------|
| `C <path>` | Report a file CREATE event |
| `M <path>` | Report a file MODIFY event |
| `D <path>` | Report a file DELETE event |
| `A` | Manually trigger an anomaly ALERT |
| `T <n> <ms>` | Set anomaly threshold & sliding window |
| `S` | Show current transfer statistics + anomaly status |
| `L` | Show recent log entries |
| `R` | Reset all statistics counters + anomaly ring |
| `X` | Clear the log buffer |
| `Q` | Quit the application |

#### Daemon Mode

Shows a periodically-refreshing dashboard with:
- Aggregate transfer statistics (bytes written, file counts, device events, alerts)
- Anomaly detection status (auto-checked every refresh cycle)
- The 8 most recent log entries

---

## Advanced Challenge: Automatic Mass-Copy Anomaly Detection ✅

The advanced challenge goal ("Detect suspicious mass-copy behavior and trigger alerts") is **fully implemented** across all three layers:

### 1. Kernel-Side Auto-Detection (`usb_audit.c`)

- Maintains a **64-entry ring buffer** of file-event timestamps.
- After every `FILE_CREATE` or `FILE_MODIFY` event, scans the ring buffer to count how many events fall within the configured **sliding time window**.
- If the count exceeds the **threshold** AND the **cooldown period** (5 s) has elapsed, the kernel **automatically**:
  - Logs a `USB_AUDIT_EVENT_ALERT` entry into the circular log buffer.
  - Emits a `printk(KERN_WARNING)` message visible in `dmesg`.
  - Increments the `alert_count` statistic.
- Configurable at runtime via `USB_AUDIT_SET_ANOMALY` / `USB_AUDIT_GET_ANOMALY` ioctls.

### 2. User-Space Auto-Check (`usb_monitor.c`)

- After every `C` / `M` command in interactive mode, queries the kernel's anomaly status.
- If `alert_triggered == 1`, displays a prominent **security warning banner**.
- Daemon mode checks every refresh cycle.
- Threshold and window configurable via `T` command or CLI `-t` / `-w` options.

### 3. Python-Side Detection (`file_tracker.py`)

- Independent sliding-window implementation using the `watchdog` library.
- Triggers `[SECURITY ALERT]` messages on the console.

#### Testing the Auto-Detection

```bash
# In the interactive monitor:
C file1.txt
C file2.txt
C file3.txt
C file4.txt
C file5.txt
C file6.txt    # ← 6th file op within 3s → ALERT fires automatically!

# Observe in dmesg:
dmesg | grep "SECURITY ALERT"
# [usb_audit] *** SECURITY ALERT *** Mass-copy detected!  6 file ops within 3000 ms (threshold=5)

# Or with custom thresholds:
sudo ./src_user/usb_monitor -i -t 3 -w 2000
# Alert fires after just 4 file ops within 2 seconds.
```

### Python Application (`file_tracker.py`)

Uses the `watchdog` library for real-time filesystem monitoring.  Implements mass-copy anomaly detection using a sliding time window (default: 5 file operations within 3 seconds triggers a `[SECURITY ALERT]`).

```bash
python3 src_user/file_tracker.py
```

---

## Verifying Kernel Logging

All kernel-side events are logged using `printk()` and are visible via `dmesg`:

```bash
# View the last 20 kernel messages
dmesg | tail -20

# Watch kernel logs in real time
dmesg -w
```

Expected kernel log output includes:

```
[usb_audit] Initialising USB File Transfer Activity Driver (Group 10)
[usb_audit] Allocated major 241, minor 0
[usb_audit] USB hotplug notifier registered
[usb_audit] Driver loaded successfully.  Device node: /dev/usb_audit
[usb_audit] Event from PID 1234: type=3 path=/media/pi/USB/test.txt
[usb_audit] USB storage device INSERTED: vendor=0x0781 product=0x5591 serial=...
[usb_audit] USB storage device REMOVED: vendor=0x0781 product=0x5591
[usb_audit] Shutting down USB File Transfer Activity Driver
[usb_audit] Driver unloaded.  Goodbye.
```

---

## Demonstration Checklist

Use this checklist to ensure the project meets all **CSC1107 demo requirements**:

### Project 15 Specific

- [ ] Driver displays file transfer statistics
- [ ] User-space C application shows transfer logs
- [ ] Kernel event logging visible via `printk()` / `dmesg`
- [ ] Advanced: mass-copy anomaly detection triggers alerts

### General Requirements

| # | Requirement | How to Verify |
|---|-------------|---------------|
| 1 | Module compilation | `make kernel` succeeds without errors |
| 2 | Module insertion | `sudo insmod src_kernel/usb_audit.ko` |
| 3 | Module removal | `sudo rmmod usb_audit` releases resources |
| 4 | Hardware detection | USB notifier logs device insert/remove events |
| 5 | App ↔ driver communication | `usb_monitor` reads/writes/ioctls to `/dev/usb_audit` |
| 6 | dmesg logging | `dmesg \| grep usb_audit` shows kernel messages |
| 7 | User app interaction | Interactive menu commands are processed by the driver |
| 8 | Clean shutdown | `run.sh` trap handler calls `rmmod` and cleans up |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `make` fails with "No such file or directory" | Install kernel headers: `sudo apt install raspberrypi-kernel-headers` |
| `insmod` fails with "Operation not permitted" | Run with `sudo` |
| `insmod` fails with "Invalid module format" | Kernel headers version mismatch; reboot after kernel update |
| `/dev/usb_audit` not created | Check `dmesg` for errors; ensure no other driver claims the major number |
| `usb_monitor` cannot open device | Ensure module is loaded: `lsmod \| grep usb_audit` |
| USB notifier not firing | Verify the USB device class is mass-storage; check `lsusb -v` |
| Python script can't find mount point | Update `USB_TARGET_PATH` in `file_tracker.py` using `lsblk` |

---

## Submission Deliverables

| File | Contents |
|------|----------|
| `Px_Groupxx-codes.zip` | All `.c`, `.h`, `.py`, `.sh` source files |
| `Px_Groupxx-report-CSC1107.docx` | Final Word report (do not paste entire source code) |
| `Px_Groupxx-CSC1107.mp4` | 8–12 minute group presentation video |
| `Px_Groupxx-demo.mp4` | Short demonstration video |

**Deadline:** Friday, 10 July 2026, 23:59.  
**Submit to:** LMS XSITE Dropbox.

---

*Group 10 — CSC1107 Operating Systems — Project 15*
