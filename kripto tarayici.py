"""
Basit Şifreleme Tarayıcısı (MVP)
--------------------------------
Bir web sitesi veya GitHub deposu linki alır, içinde eski nesil şifreleme
ifadeleri (MD5, SHA-1, RSA-1024/2048, DES, RC4 vb.) arar ve
'Risk Var' / 'Güvenli' sonucu gösterir.

Kurulum:   pip install flask requests
Çalıştır:  python kripto_tarayici.py
Adres:     http://127.0.0.1:5000

NOT: 'Güvenli' sonucu yalnızca anahtar kelime bulunmadığı anlamına gelir;
gerçek bir güvenlik denetiminin yerini tutmaz.
"""

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, render_template_string, request

app = Flask(__name__)

# ----------------------------------------------------------------------------
# Ayarlar
# ----------------------------------------------------------------------------
TIMEOUT = 8                      # saniye
MAX_BYTES = 1_000_000            # dosya başına en fazla 1 MB
MAX_SCRIPTS = 10                 # web sitesinde taranacak JS dosyası sayısı
MAX_REPO_FILES = 40              # GitHub'da taranacak dosya sayısı
MAX_REDIRECTS = 3
HEADERS = {"User-Agent": "KriptoTarayici-MVP/0.1"}

CODE_EXT = (
    ".py", ".js", ".ts", ".java", ".php", ".rb", ".go", ".cs", ".c", ".cpp",
    ".h", ".rs", ".kt", ".swift", ".conf", ".cfg", ".ini", ".yml", ".yaml",
    ".json", ".xml", ".env", ".sh", ".html", ".htm", ".txt", ".md",
)

# (etiket, regex, açıklama)
PATTERNS = [
    ("MD5", re.compile(r"\bmd5\b", re.I), "Kırılmış özet algoritması"),
    ("SHA-1", re.compile(r"\bsha-?1\b", re.I), "Zayıf özet algoritması"),
    ("RSA-1024", re.compile(r"\brsa[-_ ]?1024\b", re.I), "Yetersiz anahtar uzunluğu"),
    ("RSA-2048", re.compile(r"\brsa[-_ ]?2048\b", re.I), "Eski nesil; kuantum sonrası (PQC) geçişi planlanmalı"),
    ("DES / 3DES", re.compile(r"\b(?:3DES|DES)\b|\btriple[-_ ]?des\b", re.I), "Eski blok şifre"),
    ("RC4", re.compile(r"\brc4\b", re.I), "Kırılmış akış şifresi"),
    ("SSLv3 / TLS 1.0 / 1.1", re.compile(r"\bsslv?3\b|\btlsv?1\.[01]\b", re.I), "Eski protokol sürümü"),
]


# ----------------------------------------------------------------------------
# Güvenli HTTP istemcisi (SSRF koruması)
# ----------------------------------------------------------------------------
def host_is_public(host: str) -> bool:
    """Host'un yalnızca genel (public) IP'lere çözümlendiğini doğrular."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return False
    return True


def safe_get(url: str, accept=None) -> str:
    """Yönlendirmeleri elle takip ederek, boyut sınırıyla metin getirir."""
    for _ in range(MAX_REDIRECTS + 1):
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("Yalnızca http/https adresleri desteklenir.")
        if not host_is_public(p.hostname):
            raise ValueError("Bu adrese erişim izni yok (özel/yerel ağ).")

        headers = dict(HEADERS)
        if accept:
            headers["Accept"] = accept
        r = requests.get(url, headers=headers, timeout=TIMEOUT,
                         allow_redirects=False, stream=True)

        if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
            url = urljoin(url, r.headers.get("Location", ""))
            continue

        r.raise_for_status()
        data = r.raw.read(MAX_BYTES, decode_content=True)
        return data.decode(r.encoding or "utf-8", errors="ignore")
    raise ValueError("Çok fazla yönlendirme.")


# ----------------------------------------------------------------------------
# Tarama
# ----------------------------------------------------------------------------
def scan_text(text: str, source: str, findings: dict):
    for label, rx, desc in PATTERNS:
        if rx.search(text):
            entry = findings.setdefault(label, {"desc": desc, "sources": []})
            if source not in entry["sources"] and len(entry["sources"]) < 5:
                entry["sources"].append(source)


def scan_website(url: str, findings: dict) -> int:
    html = safe_get(url)
    scan_text(html, url, findings)
    count = 1

    base_host = urlparse(url).hostname
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    for src in scripts[:MAX_SCRIPTS]:
        full = urljoin(url, src)
        if urlparse(full).hostname != base_host:
            continue  # yalnızca aynı alan adındaki dosyalar
        try:
            scan_text(safe_get(full), full, findings)
            count += 1
        except Exception:
            continue
    return count


def scan_github(url: str, findings: dict) -> int:
    parts = [p for p in urlparse(url).path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("GitHub linki 'github.com/kullanici/depo' biçiminde olmalı.")
    owner, repo = parts[0], re.sub(r"\.git$", "", parts[1])

    api = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    import json
    tree = json.loads(safe_get(api, accept="application/vnd.github+json"))

    files = [
        t["path"] for t in tree.get("tree", [])
        if t.get("type") == "blob"
        and t["path"].lower().endswith(CODE_EXT)
        and t.get("size", 0) < 200_000
    ][:MAX_REPO_FILES]

    count = 0
    for path in files:
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
        try:
            scan_text(safe_get(raw), path, findings)
            count += 1
        except Exception:
            continue
    return count


def run_scan(url: str):
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    findings: dict = {}
    host = (urlparse(url).hostname or "").lower()
    if host in ("github.com", "www.github.com"):
        scanned = scan_github(url, findings)
    else:
        scanned = scan_website(url, findings)
    return findings, scanned


# ----------------------------------------------------------------------------
# Arayüz
# ----------------------------------------------------------------------------
PAGE = """
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Şifreleme Tarayıcısı</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#222}
  input[type=text]{width:100%;padding:12px;font-size:16px;box-sizing:border-box;border:1px solid #bbb;border-radius:8px}
  button{margin-top:12px;padding:12px 20px;font-size:16px;border:0;border-radius:8px;background:#2b5fd9;color:#fff;cursor:pointer}
  .badge{display:inline-block;margin-top:24px;padding:14px 28px;font-size:24px;font-weight:700;border-radius:10px;color:#fff}
  .risk{background:#d93025}.safe{background:#188038}
  .err{margin-top:20px;color:#b3261e}
  li{margin-bottom:8px} small{color:#666}
</style>
</head>
<body>
  <h2>🔐 Şifreleme Tarayıcısı (MVP)</h2>
  <form method="post">
    <input type="text" name="url" placeholder="https://ornek.com veya https://github.com/kullanici/depo"
           value="{{ url or '' }}" required>
    <button type="submit">Tara</button>
  </form>

  {% if error %}<div class="err">⚠️ {{ error }}</div>{% endif %}

  {% if findings is not none %}
    {% if findings %}
      <div class="badge risk">Risk Var</div>
      <p><small>{{ scanned }} dosya/sayfa tarandı.</small></p>
      <ul>
      {% for label, f in findings.items() %}
        <li><b>{{ label }}</b> — {{ f.desc }}<br>
            <small>{{ f.sources | join(', ') }}</small></li>
      {% endfor %}
      </ul>
    {% else %}
      <div class="badge safe">Güvenli</div>
      <p><small>{{ scanned }} dosya/sayfa tarandı; eski nesil şifreleme ifadesi bulunamadı.
      Bu yalnızca anahtar kelime taramasıdır, tam güvenlik garantisi vermez.</small></p>
    {% endif %}
  {% endif %}
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    url = findings = scanned = error = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        try:
            findings, scanned = run_scan(url)
        except requests.RequestException:
            error = "Adrese ulaşılamadı veya içerik alınamadı."
        except ValueError as e:
            error = str(e)
        except Exception:
            error = "Beklenmeyen bir hata oluştu."
    return render_template_string(
        PAGE, url=url, findings=findings, scanned=scanned, error=error
    )


if __name__ == "__main__":
    app.run(debug=False)
