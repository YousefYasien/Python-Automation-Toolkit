## 🛡️ Disclaimer
The scripts provided in this repository (specifically the Hash Cracker and Network Scanner) are intended for **educational and ethical testing purposes only**. Always ensure you have explicit permission before scanning networks or testing security systems that you do not own.

---

## 📄 License
This project# Python Utility Scripts

A collection of lightweight, efficient Python scripts designed for automation, network analysis, and security testing. This repository serves as a toolkit for common technical tasks, ranging from file management to cryptographic exploration.

---

## 🛠️ Featured Projects

### 1. Network Device Scanner
A tool that identifies all active devices currently connected to your local Wi-Fi network. It provides IP and MAC address details to help monitor network traffic and security.
*   **Key Features:** ARP scanning, real-time device listing.
*   **Dependencies:** `scapy` or `socket`

### 2. PIN Generator (4-Digit)
A simple but effective script that generates an exhaustive list of all possible 4-digit PIN combinations (0000–9999).
*   **Use Case:** Ideal for testing password strength or generating datasets for brute-force simulations.
*   **Output:** Generates a `.txt` file with 10,000 unique combinations.

### 3. Simple Hash Cracker
A security utility that attempts to reverse cryptographic hashes (like MD5 or SHA-256) by comparing them against common wordlists or brute-force attempts.
*   **Functionality:** Supports multiple hashing algorithms via the `hashlib` library.

### 4. Smart File Merger
A productivity tool that combines multiple files (PDFs, text files, or CSVs) into a single, organized document.
*   **Features:** Maintains original file order and handles various encoding formats.

---

## 🚀 Getting Started

### Prerequisites
Ensure you have **Python 3.x** installed on your system. You can check your version by running:
```bash
python --version
