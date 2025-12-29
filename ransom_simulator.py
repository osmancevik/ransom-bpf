import os
import time
import random

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

    print(f"[*] Saldırı başlatılıyor... Hedef: {TARGET_DIR}")

    files = [f for f in os.listdir(TARGET_DIR) if os.path.isfile(os.path.join(TARGET_DIR, f))]

    # Kendimizi (scripti) veya zaten şifreli dosyaları şifrelemeyelim
    files = [f for f in files if not f.endswith(ENCRYPTED_EXTENSION) and f != "ransom_simulator.py"]

    print(f"[*] Toplam {len(files)} kurban dosya bulundu.")
    time.sleep(1) # Kullanıcıya heyecan verelim :)

    for i, filename in enumerate(files):
        full_path = os.path.join(TARGET_DIR, filename)

        try:
            # --- ADIM 1: DOSYAYI OKU VE ŞİFRELE (SİMÜLASYON) ---
            with open(full_path, "rb+") as f:
                content = f.read()
                # Basit bir manipülasyon: Byte'ları ters çevir (WRITE işlemini tetikler)
                encrypted_content = content[::-1]
                f.seek(0)
                f.write(encrypted_content)
                f.truncate()

            # --- ADIM 2: UZANTIYI DEĞİŞTİR (RENAME) ---
            new_path = full_path + ENCRYPTED_EXTENSION
            os.rename(full_path, new_path)

            print(f"[+] Şifrelendi ({i+1}/{len(files)}): {filename} -> {filename}{ENCRYPTED_EXTENSION}")

            # --- Eşik Simülasyonu ---
            # RansomBPF'nin Hız Analizini (H1) test etmek için bekleme süresini azaltabilirsin.
            # Şu an 0.05 sn bekleme ile saniyede yaklaşık 20 dosya işler.
            time.sleep(0.02)

        except Exception as e:
            print(f"[!] Hata oluştu {filename}: {e}")

    # --- ADIM 3: FİDYE NOTU BIRAK ---
    note_path = os.path.join(TARGET_DIR, RANSOM_NOTE_NAME)
    with open(note_path, "w") as f:
        f.write(RANSOM_NOTE_CONTENT)
    print(f"[*] Fidye notu bırakıldı: {note_path}")
    print("[*] SALDIRI TAMAMLANDI.")

if __name__ == "__main__":
    simulate_encryption_activity()