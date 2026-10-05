# 🛡️ Kernel Guardian v2.1

### Linux Kernel Security Monitoring & Risk Assessment System

**Kernel Guardian** is a Linux-based security monitoring system designed to observe system activity, detect potentially suspicious behavior, assess security risks, and present the results through a unified security dashboard.

The project combines **Linux kernel-level monitoring, process monitoring, file integrity monitoring, network monitoring, risk assessment, and real-time security visualization** into a single security-oriented platform.

---

## 🚀 Overview

Modern Linux systems generate a large amount of system activity involving processes, files, network connections, and kernel events.

Kernel Guardian provides a centralized monitoring layer that collects these events and transforms them into security information through multiple components:

```text
                    ┌───────────────────────────┐
                    │       Linux System        │
                    │  Processes / Files / Net   │
                    └─────────────┬─────────────┘
                                  │
                     ┌────────────▼────────────┐
                     │   Kernel Event Monitor  │
                     │     kernel_guardian     │
                     └────────────┬────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
       ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
       │ File        │     │ Network     │     │ Process     │
       │ Integrity   │     │ Monitor     │     │ Monitoring  │
       │ guardian_fim│     │guardian_net │     │kernel_guard │
       └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  │
                         ┌────────▼────────┐
                         │   Risk Engine   │
                         │  guardian_risk  │
                         └────────┬────────┘
                                  │
                         ┌────────▼────────┐
                         │ Unified Security│
                         │    Dashboard    │
                         │guardian_dashboard│
                         └─────────────────┘
```

---

# ✨ Key Features

### 🔹 Linux Kernel Monitoring
- Kernel-level event monitoring
- Process creation/fork event detection
- Linux tracepoint-based monitoring
- Kernel module integration
- Kernel event logging

### 🔹 Process Security Monitoring
- Monitors process activity
- Tracks process creation events
- Generates security events
- Supports suspicious activity analysis

### 🔹 File Integrity Monitoring

Monitors important filesystem activity including:

- File writes
- Attribute changes
- Critical system files
- Security-sensitive paths

Example monitored file:

```text
/etc/passwd
```

Security-sensitive changes can be assigned high or critical risk scores.

### 🔹 Network Security Monitoring

Kernel Guardian reads Linux networking information and monitors:

- TCP connections
- TCP6 connections
- UDP connections
- UDP6 connections
- Local listening services
- Network connection state
- Network-related risk events

The network monitor operates using Linux `/proc` networking tables.

### 🔹 Risk Assessment Engine

Security events are converted into risk assessments.

Each event receives a risk score and severity classification:

| Severity | Description |
|---|---|
| 🟢 LOW | Normal or low-risk activity |
| 🟡 MEDIUM | Activity requiring attention |
| 🟠 HIGH | Potentially suspicious activity |
| 🔴 CRITICAL | Highly sensitive or dangerous activity |

Risk scores range from:

```text
0 → 100
```

### 🔹 Unified Security Dashboard

Phase 6 provides a terminal-based security dashboard showing:

- Component status
- Kernel events
- Security alerts
- Risk assessments
- Risk severity distribution
- Risk category distribution
- Highest detected risk
- Recent critical alerts
- Automatic dashboard refresh

Example:

```text
======================================================================
                    KERNEL GUARDIAN v2.1
                 UNIFIED SECURITY DASHBOARD
======================================================================

COMPONENT STATUS
----------------------------------------------------------------------
Process Monitor           : RUNNING
File Integrity            : RUNNING
Network Monitor           : RUNNING
Risk Engine               : RUNNING

LOG STATISTICS
----------------------------------------------------------------------
Kernel events             : 11670
Security alerts           : 3394
Risk assessments          : 14652

RISK SEVERITY DISTRIBUTION
----------------------------------------------------------------------
LOW                       : 8879
MEDIUM                    : 5513
HIGH                      : 248
CRITICAL                  : 12

Highest risk score        : 100
```

---

# 🏗️ Architecture

Kernel Guardian is organized into multiple monitoring and analysis layers.

```text
┌─────────────────────────────────────────────┐
│              Linux Operating System         │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│          Kernel Event Collection             │
│       Linux Tracepoints / Kernel Module      │
└──────────────────────┬──────────────────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
     Process        File         Network
     Monitor      Integrity      Monitor
          │            │            │
          └────────────┼────────────┘
                       ▼
              ┌─────────────────┐
              │   Event Logs    │
              │     JSONL       │
              └────────┬────────┘
                       ▼
              ┌─────────────────┐
              │   Risk Engine   │
              └────────┬────────┘
                       ▼
              ┌─────────────────┐
              │ Security        │
              │ Dashboard       │
              └─────────────────┘
```

---

# 📁 Project Structure

```text
kernel-guardian/
│
├── collector/
│   ├── guardian_collector.py
│   └── guardian_collector_v1.4_backup.py
│
├── detector/
│   └── guardian_detector.py
│
├── cpp/
│   ├── kernel_guardian.cpp
│   │
│   ├── phase3/
│   │   └── file_integrity_monitor.cpp
│   │
│   ├── phase4/
│   │   └── network_monitor.cpp
│   │
│   ├── phase5/
│   │   └── risk_engine.cpp
│   │
│   └── phase6/
│       └── security_dashboard.cpp
│
├── kernel/
│   ├── guardian_main.c
│   └── Makefile
│
├── guardian_monitor.sh
├── setup_guardian.sh
│
├── kernel_guardian
├── guardian_fim
├── guardian_network
├── guardian_risk
├── guardian_dashboard
│
├── .gitignore
└── README.md
```

---

# 🧩 Components

| Component | Purpose |
|---|---|
| `kernel_guardian` | Process and kernel event monitoring |
| `guardian_fim` | File integrity monitoring |
| `guardian_network` | Network activity monitoring |
| `guardian_risk` | Security risk assessment |
| `guardian_dashboard` | Unified security dashboard |
| `guardian_main.c` | Linux kernel module |
| `guardian_collector.py` | Event collection/processing |
| `guardian_detector.py` | Security event detection |
| `guardian_monitor.sh` | Monitoring/automation helper |
| `setup_guardian.sh` | Project setup and initialization |

---

# 🛠️ Technology Stack

### Programming Languages

- **C**
- **C++**
- **Python**
- **Bash**

### Linux Technologies

- Linux Kernel
- Linux Kernel Modules
- Linux Tracepoints
- `/proc` filesystem
- `tracefs`
- `debugfs`
- Kernel event monitoring

### Development Tools

- GCC / G++
- GNU Make
- Git
- GitHub
- Ubuntu Linux

---

# 💻 Requirements

Kernel Guardian is designed for Linux systems.

Recommended environment:

```text
OS              : Ubuntu Linux
Compiler        : GCC / G++
C++ Standard    : C++17
Build System    : GNU Make
Python          : Python 3
Privileges      : sudo/root for system-level monitoring
```

Some components require elevated privileges because they interact with kernel tracing, filesystem monitoring, or networking information.

---

# ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/oghacker001/kernel-guardian.git
cd kernel-guardian
```

Make the setup script executable:

```bash
chmod +x setup_guardian.sh
```

Run the setup:

```bash
./setup_guardian.sh
```

---

# 🔨 Building

Build the C++ components using the provided source files.

Example:

```bash
g++ -std=c++17 -O2 cpp/kernel_guardian.cpp -o kernel_guardian
```

Dashboard:

```bash
g++ -std=c++17 -O2 \
    cpp/phase6/security_dashboard.cpp \
    -o guardian_dashboard
```

The kernel component can be built using:

```bash
cd kernel
make
```

---

# ▶️ Running Kernel Guardian

Because several monitoring components interact with system-level resources, they may require `sudo`.

### Process Monitor

From the project root:

```bash
sudo ./kernel_guardian
```

### File Integrity Monitor

```bash
sudo ./guardian_fim
```

### Network Monitor

```bash
sudo ./guardian_network
```

### Risk Engine

```bash
sudo ./guardian_risk
```

### Unified Dashboard

```bash
./guardian_dashboard
```

The dashboard automatically refreshes and displays the current security state.

---

# 📊 Security Event Pipeline

Kernel Guardian follows the following processing model:

```text
System Activity
       │
       ▼
Event Collection
       │
       ▼
Event Classification
       │
       ▼
Risk Scoring
       │
       ▼
Severity Assignment
       │
       ▼
JSONL Event Storage
       │
       ▼
Unified Dashboard
```

Example security event:

```text
FILE | ATTRIBUTE_CHANGE | score=100 | /etc/passwd
```

Another example:

```text
NETWORK | TCP | risk=10 | LOW
```

---

# 🔐 Security Model

Kernel Guardian uses a risk-based approach instead of treating every system event as malicious.

Events are evaluated according to their type and security relevance.

For example:

```text
Normal network connection
        ↓
Low risk

Unexpected filesystem modification
        ↓
Higher risk

Modification of sensitive system file
        ↓
Critical risk
```

This provides a foundation for developing more advanced detection and correlation capabilities.

---

# 📈 Example Monitoring Results

During testing, Kernel Guardian successfully generated and processed thousands of system events.

Example dashboard statistics:

```text
Kernel events       : 11670
Security alerts     : 3394
Risk assessments    : 14652

LOW                 : 8879
MEDIUM              : 5513
HIGH                : 248
CRITICAL            : 12

Highest risk score  : 100
```

The system also demonstrated detection of sensitive filesystem activity such as changes involving:

```text
/etc/passwd
```

---

# 🧪 Testing

Kernel Guardian can be tested by running the monitoring components simultaneously.

Example:

### Terminal 1

```bash
sudo ./kernel_guardian
```

### Terminal 2

```bash
sudo ./guardian_fim
```

### Terminal 3

```bash
sudo ./guardian_network
```

### Terminal 4

```bash
sudo ./guardian_risk
```

### Terminal 5

```bash
./guardian_dashboard
```

The dashboard can then be used to observe the collected events and risk assessments.

---

# 🗃️ Logging

Kernel Guardian stores monitoring information in structured log files.

Typical files include:

```text
guardian_events.jsonl
guardian_alerts.jsonl
guardian_risk.jsonl
```

These logs contain information used by the monitoring and risk-analysis components.

Runtime logs are excluded from version control through `.gitignore`.

---

# 🔒 Sensitive Files

Private cryptographic signing keys are intentionally excluded from Git.

Examples:

```text
*.priv
*.key
*.pem
```

Kernel build artifacts and runtime logs are also excluded.

**Never commit private signing keys or credentials to a public repository.**

---

# 🧠 Project Phases

Kernel Guardian was developed incrementally through multiple phases:

### Phase 1–2
Foundation and kernel/process monitoring.

### Phase 3
File Integrity Monitoring.

### Phase 4
Network Security Monitoring.

### Phase 5
Risk Engine and security severity assessment.

### Phase 6
Unified Security Dashboard.

The final system integrates these components into a single security monitoring architecture.

---

# 🎯 Project Objectives

The main objectives of Kernel Guardian are:

- Understand Linux kernel monitoring mechanisms.
- Explore Linux kernel modules and tracepoints.
- Monitor process-level system activity.
- Detect filesystem changes.
- Monitor network connections.
- Build a risk-based security analysis engine.
- Integrate multiple security components.
- Provide a unified security dashboard.
- Gain practical experience with Linux system programming.
- Apply C/C++ to operating-system and security engineering.

---

# 🔮 Future Improvements

Potential future enhancements include:

- Real-time process risk scoring
- User and privilege escalation monitoring
- Advanced network anomaly detection
- IP reputation analysis
- Process-to-network correlation
- Persistent baseline management
- File hash verification
- Alert notification system
- Email/Telegram security alerts
- Web-based security dashboard
- Historical security analytics
- Machine-learning-based anomaly detection
- Systemd service integration
- Container monitoring
- Improved kernel event correlation

---

# ⚠️ Disclaimer

Kernel Guardian is an educational and research-oriented security monitoring project.

It should **not** be considered a replacement for a production-grade Endpoint Detection and Response (EDR), SIEM, antivirus, or intrusion detection system.

Run system-level components only on systems where you have appropriate authorization.

---

# 👨‍💻 Author

**Nishant Gupta**

Computer Science & Information Technology

Linux • C/C++ • Cybersecurity • System Programming • AI/ML

GitHub:  
https://github.com/oghacker001

Project:  
https://github.com/oghacker001/kernel-guardian

---

# ⭐ Support

If you find this project useful or interesting, consider giving the repository a ⭐ on GitHub.

---

## 📜 License

This project is currently provided for educational and research purposes.
