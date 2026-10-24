import os
import subprocess
import re
import glob
import urllib.parse

# Ayarlar
REQUESTS_DIR = "./requests"  # Request dosyalarının bulunduğu klasör
SQLMAP_PATH = "sqlmap"      # Sisteminizde sqlmap globalde tanımlı değilse tam yolunu yazın (örn: /opt/sqlmap/sqlmap.py)

def extract_parameters_from_request(file_path):
    """
    HTTP request dosyasını okuyarak GET parametrelerini, Cookie anahtarlarını 
    ve POST body parametrelerini otomatik olarak ayıklar.
    """
    params = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return params

    # Header ve Body kısımlarını ayıralım (HTTP standardı boş satır ile ayrılır)
    parts = content.split('\r\n\r\n') if '\r\n\r\n' in content else content.split('\n\n')
    headers_part = parts[0]
    body_part = parts[1] if len(parts) > 1 else ""

    lines = headers_part.splitlines()
    if not lines:
        return params

    # 1. Request Satırı (GET /path?id=1 HTTP/1.1) üzerinden GET parametrelerini bul
    request_line = lines[0]
    match = re.match(r"([A-Z]+)\s+([^\s]+)\s+HTTP", request_line)
    if match:
        uri = match.group(2)
        parsed_url = urllib.parse.urlparse(uri)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        params.extend(query_params.keys())

    # 2. Cookie başlığından parametre isimlerini bul
    for line in lines:
        if line.lower().startswith("cookie:"):
            cookie_content = line.split(":", 1)[1].strip()
            for cookie in cookie_content.split(';'):
                if '=' in cookie:
                    c_name = cookie.split('=')[0].strip()
                    params.append(c_name)

    # 3. POST Body (x-www-form-urlencoded) parametrelerini bul
    is_form_post = any("content-type: application/x-www-form-urlencoded" in l.lower() for l in lines)
    if body_part and is_form_post:
        post_params = urllib.parse.parse_qs(body_part)
        params.extend(post_params.keys())

    # Benzersiz parametre isimlerini liste olarak döndür
    return list(set(params))

def analyze_sqlmap_output(stdout_text):
    """
    SQLMap stdout çıktısını inceleyerek yanlış pozitiflere (not injectable vb.)
    takılmadan kesin zafiyet durumunu, parametreleri ve DBMS bilgisini tespit eder.
    """
    is_vulnerable = False
    vulnerable_params = []
    dbms = "Bilinmiyor"

    lower_text = stdout_text.lower()
    print(lower_text)
    # Pozitif zafiyet tespiti için SQLMap'in kendi anahtar kalıbı
    if "is vulnerable" in lower_text:
        is_vulnerable = True

        # Parametre adını yakala (Örn: GET parameter 'username' is vulnerable)
        param_matches = re.findall(r"(?:get|post|cookie|custom)?\s*parameter '([^']+)' is vulnerable", lower_text, re.IGNORECASE)
        if param_matches:
            vulnerable_params = list(set(param_matches))
        else:
            # Alternatif regex denemesi
            alt_matches = re.findall(r"'([^']+)' is vulnerable", lower_text, re.IGNORECASE)
            vulnerable_params = list(set(alt_matches)) if alt_matches else ["Bilinmeyen Parametre"]

    # DBMS (Veritabanı) Tespiti
    dbms_match = re.search(r"back-end dbms:\s*([^\n\r]+)", lower_text, re.IGNORECASE)
    if dbms_match:
        dbms = dbms_match.group(1).strip().upper()

    return is_vulnerable, vulnerable_params, dbms

def main():
    if not os.path.exists(REQUESTS_DIR):
        print(f"[-] Hata: '{REQUESTS_DIR}' klasörü bulunamadı.")
        return

    # Klasördeki tüm .txt veya .req uzantılı request dosyalarını bul
    request_files = glob.glob(os.path.join(REQUESTS_DIR, "*.txt")) + glob.glob(os.path.join(REQUESTS_DIR, "*.req"))

    if not request_files:
        print(f"[-] '{REQUESTS_DIR}' klasöründe taranacak request dosyası bulunamadı.")
        return

    print(f"[+] Toplam {len(request_files)} adet request dosyası bulundu. Tarama başlatılıyor...\n")
    
    report = {}

    for req_file in request_files:
        print(f"[*] Taranıyor: {os.path.basename(req_file)}")
        
        # Request dosyasından parametreleri otomatik çıkar
        extracted_params = extract_parameters_from_request(req_file)
        
        # SQLMap Komutu Oluşturma
        cmd = [
            SQLMAP_PATH,
            "-r", req_file,
            "--batch",
            "--disable-coloring",
            "--level=1",
            "--risk=1",
            "--flush-session"
        ]

        # Eğer otomatik parametre bulunduysa -p ile ekleyelim
        if extracted_params:
            param_string = ",".join(extracted_params)
            cmd.extend(["-p", param_string])
            print(f"    [+] Hedef alınan parametreler (-p): {param_string}")
        else:
            print(f"    [-] Otomatik parametre bulunamadı, SQLMap kendi seçecek.")

        try:
            # Subprocess ile komutu çalıştırıp çıktıyı yakalıyoruz
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            stdout, _ = process.communicate()

            # Çıktıyı analiz et
            vulnerable, params, dbms = analyze_sqlmap_output(stdout)

            if vulnerable:
                print(f"    [!] ZAFİYET TESPİT EDİLDİ!")
                print(f"        -> Parametre(ler): {params}")
                print(f"        -> DBMS: {dbms}")
                report[req_file] = {"status": "Vulnerable", "parameters": params, "dbms": dbms}
            else:
                print(f"    [-] Zafiyet bulunamadı.")
                report[req_file] = {"status": "Safe", "parameters": [], "dbms": None}

        except Exception as e:
            print(f"    [x] Çalıştırma hatası: {str(e)}")
            report[req_file] = {"status": "Error", "details": str(e)}
        
        print("-" * 50)

    # Özet Rapor Yazdırma
    print("\n" + "="*20 + " GENEL TARAMA RAPORU " + "="*20)
    vuln_count = sum(1 for info in report.values() if info["status"] == "Vulnerable")
    
    for file, info in report.items():
        print(f"Dosya : {os.path.basename(file)}")
        print(f"Durum : {info['status']}")
        if info['status'] == 'Vulnerable':
            print(f"Param : {info['parameters']}")
            print(f"DBMS  : {info['dbms']}")
        print("~" * 40)
    
    print(f"\n[*] Özet: Toplam {len(request_files)} dosyadan {vuln_count} tanesinde SQLi zafiyeti bulundu.")

if __name__ == "__main__":
    main()
