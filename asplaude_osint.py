#!/usr/bin/env python3
# Asplaude OSINT Dashboard
# By Aspa 

import os
import sys
import json
import time
import hashlib
import socket
import ssl
import re
import struct
import ipaddress
from datetime import datetime
from urllib.parse import urlparse

# ── Auto-install dependencies ──────────────────────────────────────────────
def install(pkg):
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q", "--break-system-packages"])

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.columns import Columns
    from rich.align import Align
    from rich import box
    from rich.prompt import Prompt
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.syntax import Syntax
except ImportError:
    print("Installing rich..."); install("rich")
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.columns import Columns
    from rich.align import Align
    from rich import box
    from rich.prompt import Prompt
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.syntax import Syntax

try:
    import requests
except ImportError:
    print("Installing requests..."); install("requests")
    import requests

try:
    from PIL import Image
    import piexif
except ImportError:
    print("Installing Pillow + piexif..."); install("Pillow"); install("piexif")
    from PIL import Image
    import piexif

try:
    import qrcode
except ImportError:
    print("Installing qrcode..."); install("qrcode[pil]")
    import qrcode

try:
    from pyzbar.pyzbar import decode as qr_decode
except ImportError:
    print("Installing pyzbar..."); install("pyzbar")
    try:
        from pyzbar.pyzbar import decode as qr_decode
        QR_READ = True
    except:
        QR_READ = False
else:
    QR_READ = True

console = Console()

ASCII_LOGO = """
 █████╗ ███████╗██████╗ ██╗      █████╗ ██╗   ██╗██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝
███████║███████╗██████╔╝██║     ███████║██║   ██║██║  ██║█████╗  
██╔══██║╚════██║██╔═══╝ ██║     ██╔══██║██║   ██║██║  ██║██╔══╝  
██║  ██║███████║██║     ███████╗██║  ██║╚██████╔╝██████╔╝███████╗
╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
                    ██████╗ ███████╗██╗███╗   ██╗████████╗
                   ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
                   ██║   ██║███████╗██║██╔██╗ ██║   ██║   
                   ██║   ██║╚════██║██║██║╚██╗██║   ██║   
                   ╚██████╔╝███████║██║██║ ╚████║   ██║   
                    ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
"""

MENU_ITEMS = [
    ("1",  "🔍", "EXIF / Metadata Oxuyucu",      "exif"),
    ("2",  "🌐", "IP / Domain / WHOIS Analizi",   "ip_domain"),
    ("3",  "👤", "Username Axtarışı",             "username"),
    ("4",  "🔐", "Breach Yoxlayıcı",              "breach"),
    ("5",  "📡", "Şəbəkə Cihazları (ARP Scan)",   "arp"),
    ("6",  "#",  "Hash Hesablayıcı",              "hash_tool"),
    ("7",  "🛡️", "URL Təhlükə Analizi",           "url_check"),
    ("8",  "🔑", "Şifrə Güc Analizi",             "password"),
    ("9",  "📧", "Email Analizi",                 "email"),
    ("10", "🔒", "SSL Sertifikat Yoxlayıcı",      "ssl_check"),
    ("11", "📱", "Sosial Media Analizi",          "social"),
    ("12", "📷", "QR Kod Oxuyucu / Yaradan",      "qr"),
    ("0",  "🚪", "Çıxış",                        "exit"),
]

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    console.print(Text(ASCII_LOGO, style="bold cyan"))
    console.print(Align.center(Text("[ OSINT ]  •  By Aspa ", style="dim white")))
    console.print()

def show_menu():
    table = Table(box=box.ROUNDED, border_style="cyan", show_header=True, header_style="bold cyan")
    table.add_column("№", style="bold yellow", width=4)
    table.add_column("İkon", width=4)
    table.add_column("Funksiya", style="white")

    for num, icon, name, _ in MENU_ITEMS:
        style = "bold red" if num == "0" else "white"
        table.add_row(num, icon, Text(name, style=style))

    console.print(Panel(table, title="[bold cyan]ANA MENYU[/bold cyan]", border_style="cyan"))

def back_prompt():
    console.print()
    Prompt.ask("[dim]↩  Ana menyuya qayıtmaq üçün Enter basın[/dim]", default="")

def with_spinner(msg, fn):
    with Progress(SpinnerColumn(), TextColumn(f"[cyan]{msg}..."), transient=True) as p:
        p.add_task("", total=None)
        return fn()

# ── 1. EXIF ────────────────────────────────────────────────────────────────
def exif():
    console.print(Panel("[bold cyan]🔍 EXIF / Metadata Oxuyucu[/bold cyan]", border_style="cyan"))
    path = Prompt.ask("[yellow]Şəkil faylının yolu[/yellow]").strip().strip('"')
    if not os.path.exists(path):
        console.print("[red]Fayl tapılmadı![/red]"); back_prompt(); return

    try:
        img = Image.open(path)
        table = Table(box=box.SIMPLE, border_style="cyan", show_header=True, header_style="bold cyan")
        table.add_column("Alan", style="yellow", min_width=24)
        table.add_column("Dəyər", style="white")

        table.add_row("Fayl adı", os.path.basename(path))
        table.add_row("Format", img.format or "?")
        table.add_row("Ölçü", f"{img.width} x {img.height} px")
        table.add_row("Mod", img.mode)
        fsize = os.path.getsize(path)
        table.add_row("Fayl ölçüsü", f"{fsize/1024:.1f} KB")

        exif_data = img._getexif() if hasattr(img, '_getexif') else None
        gps_lat = gps_lon = None

        if exif_data:
            from PIL.ExifTags import TAGS, GPSTAGS
            for tag_id, val in exif_data.items():
                tag = TAGS.get(tag_id, str(tag_id))
                if tag == "GPSInfo":
                    gps = {}
                    for k, v in val.items():
                        gps[GPSTAGS.get(k, k)] = v
                    try:
                        def dms(d): return d[0]+d[1]/60+d[2]/3600
                        lat = dms(gps['GPSLatitude'])
                        if gps.get('GPSLatitudeRef') == 'S': lat = -lat
                        lon = dms(gps['GPSLongitude'])
                        if gps.get('GPSLongitudeRef') == 'W': lon = -lon
                        gps_lat, gps_lon = lat, lon
                        table.add_row("📍 GPS Koordinat", f"{lat:.6f}, {lon:.6f}")
                        table.add_row("📍 Google Maps", f"https://maps.google.com/?q={lat},{lon}")
                    except: pass
                elif tag not in ("MakerNote","UserComment") and isinstance(val,(str,int,float,bytes)):
                    v = val.decode('utf-8','ignore') if isinstance(val,bytes) else str(val)
                    if len(v) < 120:
                        table.add_row(tag, v)
        else:
            table.add_row("[dim]EXIF məlumatı[/dim]", "[dim]Tapılmadı[/dim]")

        console.print(table)
        if gps_lat:
            console.print(f"\n[bold green]📍 GPS aşkarlandı![/bold green] {gps_lat:.6f}, {gps_lon:.6f}")
    except Exception as e:
        console.print(f"[red]Xəta: {e}[/red]")
    back_prompt()

# ── 2. IP / Domain ─────────────────────────────────────────────────────────
def ip_domain():
    console.print(Panel("[bold cyan]🌐 IP / Domain / WHOIS Analizi[/bold cyan]", border_style="cyan"))
    target = Prompt.ask("[yellow]IP və ya domain[/yellow]").strip()

    def run():
        results = {}
        # Resolve
        try:
            ip = socket.gethostbyname(target)
            results['IP'] = ip
        except:
            ip = target
            results['IP'] = ip

        # ip-api
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=6).json()
            if r.get('status') == 'success':
                results['Ölkə'] = r.get('country','?')
                results['Region'] = r.get('regionName','?')
                results['Şəhər'] = r.get('city','?')
                results['ISP'] = r.get('isp','?')
                results['Org'] = r.get('org','?')
                results['Timezone'] = r.get('timezone','?')
                results['Koordinat'] = f"{r.get('lat')}, {r.get('lon')}"
                results['AS'] = r.get('as','?')
        except: pass

        # Reverse DNS
        try:
            host = socket.gethostbyaddr(ip)[0]
            results['Reverse DNS'] = host
        except: pass

        # Port scan (common ports)
        open_ports = []
        for port in [21,22,23,25,53,80,443,3306,8080,8443]:
            s = socket.socket()
            s.settimeout(0.4)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(str(port))
            s.close()
        results['Açıq Portlar'] = ', '.join(open_ports) if open_ports else 'Tapılmadı'

        return results

    results = with_spinner("Analiz edilir", run)

    table = Table(box=box.SIMPLE, border_style="cyan", header_style="bold cyan")
    table.add_column("Alan", style="yellow", min_width=20)
    table.add_column("Dəyər", style="white")
    for k,v in results.items():
        table.add_row(k, str(v))
    console.print(table)
    back_prompt()

# ── 3. Username ─────────────────────────────────────────────────────────────
def username():
    console.print(Panel("[bold cyan]👤 Username Axtarışı[/bold cyan]", border_style="cyan"))
    uname = Prompt.ask("[yellow]İstifadəçi adı[/yellow]").strip()

    platforms = [
        ("GitHub",     f"https://github.com/{uname}"),
        ("Twitter/X",  f"https://twitter.com/{uname}"),
        ("Instagram",  f"https://instagram.com/{uname}"),
        ("TikTok",     f"https://tiktok.com/@{uname}"),
        ("Reddit",     f"https://reddit.com/user/{uname}"),
        ("Pinterest",  f"https://pinterest.com/{uname}"),
        ("Twitch",     f"https://twitch.tv/{uname}"),
        ("YouTube",    f"https://youtube.com/@{uname}"),
        ("LinkedIn",   f"https://linkedin.com/in/{uname}"),
        ("Telegram",   f"https://t.me/{uname}"),
        ("Medium",     f"https://medium.com/@{uname}"),
        ("Dev.to",     f"https://dev.to/{uname}"),
    ]

    table = Table(box=box.SIMPLE, border_style="cyan", header_style="bold cyan")
    table.add_column("Platform", style="yellow", min_width=14)
    table.add_column("Status", width=10)
    table.add_column("URL", style="dim white")

    headers = {'User-Agent': 'Mozilla/5.0'}
    found = 0

    with Progress(SpinnerColumn(), TextColumn("[cyan]Yoxlanılır..."), transient=True) as p:
        p.add_task("", total=None)
        for name, url in platforms:
            try:
                r = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
                if r.status_code == 200:
                    status = Text("✓ VAR", style="bold green")
                    found += 1
                else:
                    status = Text("✗ Yox", style="dim red")
            except:
                status = Text("? Xəta", style="dim yellow")
            table.add_row(name, status, url)

    console.print(table)
    console.print(f"\n[bold green]Tapıldı: {found}/{len(platforms)} platformda[/bold green]")
    back_prompt()

# ── 4. Breach ──────────────────────────────────────────────────────────────
def breach():
    console.print(Panel("[bold cyan]🔐 Breach Yoxlayıcı[/bold cyan]", border_style="cyan"))
    email = Prompt.ask("[yellow]Email ünvanı[/yellow]").strip()

    def run():
        # k-anonymity SHA1 check via HIBP
        import hashlib
        sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                           headers={"User-Agent":"Asplaude-OSINT"}, timeout=8)
            for line in r.text.splitlines():
                h, count = line.split(':')
                if h == suffix:
                    return f"⚠️  {email} — {int(count):,} dəfə sızdırılıb!"
            return f"✅  {email} — heç bir sızıntıda tapılmadı."
        except Exception as e:
            return f"[red]Xəta: {e}[/red]"

    # Domain check
    domain = email.split('@')[-1] if '@' in email else ''

    result = with_spinner("HIBP sorğusu", run)
    console.print(f"\n[bold]{result}[/bold]")

    if domain:
        console.print(f"\n[cyan]Domain:[/cyan] {domain}")
        try:
            ip = socket.gethostbyname(domain)
            console.print(f"[cyan]IP:[/cyan] {ip}")
        except:
            console.print("[red]Domain həll edilə bilmədi[/red]")

    back_prompt()

# ── 5. ARP Scan ────────────────────────────────────────────────────────────
def arp():
    console.print(Panel("[bold cyan]📡 Şəbəkə Cihazları (ARP Scan)[/bold cyan]", border_style="cyan"))

    try:
        import subprocess
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        subnet = '.'.join(local_ip.split('.')[:3]) + '.0/24'
        console.print(f"[cyan]Şəbəkə:[/cyan] {subnet}  [cyan]Öz IP:[/cyan] {local_ip}\n")
    except:
        console.print("[red]Şəbəkə məlumatı alına bilmədi[/red]")
        back_prompt(); return

    try:
        from scapy.all import ARP, Ether, srp
        SCAPY = True
    except ImportError:
        SCAPY = False

    table = Table(box=box.SIMPLE, border_style="cyan", header_style="bold cyan")
    table.add_column("IP", style="yellow", min_width=16)
    table.add_column("MAC", style="cyan", min_width=18)
    table.add_column("İstehsalçı", style="white")
    table.add_column("Status", style="green")

    found = []

    if SCAPY:
        with Progress(SpinnerColumn(), TextColumn("[cyan]ARP scan..."), transient=True) as p:
            p.add_task("", total=None)
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet)
                ans, _ = srp(pkt, timeout=2, verbose=False)
                for _, rcv in ans:
                    found.append((rcv.psrc, rcv.hwsrc))
            except Exception as e:
                console.print(f"[red]Scapy xəta: {e} — root/admin lazımdır[/red]")
    else:
        # Fallback: ping sweep
        console.print("[yellow]⚠ Scapy yoxdur, ping sweep istifadə edilir...[/yellow]\n")
        base = '.'.join(local_ip.split('.')[:3])
        with Progress(SpinnerColumn(), TextColumn("[cyan]Taranır..."), transient=True) as p:
            task = p.add_task("", total=254)
            for i in range(1, 255):
                ip = f"{base}.{i}"
                r = os.system(f"ping -c1 -W1 {ip} > /dev/null 2>&1" if os.name!='nt'
                              else f"ping -n 1 -w 500 {ip} > nul 2>&1")
                if r == 0:
                    found.append((ip, "N/A"))
                p.advance(task)

    def get_vendor(mac):
        try:
            r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
            return r.text.strip() if r.status_code==200 else "?"
        except: return "?"

    for ip, mac in found:
        vendor = get_vendor(mac) if mac != "N/A" else "?"
        status = Text("● Online", style="bold green")
        table.add_row(ip, mac, vendor, status)

    if not found:
        console.print("[yellow]Heç bir cihaz tapılmadı. Root/admin icazəsi lazım ola bilər.[/yellow]")
    else:
        console.print(table)
        console.print(f"\n[bold green]Cəmi {len(found)} cihaz tapıldı[/bold green]")

    back_prompt()

# ── 6. Hash ────────────────────────────────────────────────────────────────
def hash_tool():
    console.print(Panel("[bold cyan]# Hash Hesablayıcı[/bold cyan]", border_style="cyan"))
    choice = Prompt.ask("[yellow]Nə hashlemek isteyirsiniz?\n  [1] Mətn\n  [2] Fayl\nSeçim[/yellow]", default="1")

    if choice == "1":
        text = Prompt.ask("[yellow]Mətn[/yellow]")
        data = text.encode()
    else:
        path = Prompt.ask("[yellow]Fayl yolu[/yellow]").strip().strip('"')
        if not os.path.exists(path):
            console.print("[red]Fayl tapılmadı![/red]"); back_prompt(); return
        with open(path,'rb') as f:
            data = f.read()

    table = Table(box=box.SIMPLE, border_style="cyan", header_style="bold cyan")
    table.add_column("Alqoritm", style="yellow", min_width=10)
    table.add_column("Hash", style="cyan")

    for alg in ['md5','sha1','sha224','sha256','sha384','sha512']:
        h = hashlib.new(alg, data).hexdigest()
        table.add_row(alg.upper(), h)

    console.print(table)
    back_prompt()

# ── 7. URL Check ───────────────────────────────────────────────────────────
def url_check():
    console.print(Panel("[bold cyan]🛡️ URL Təhlükə Analizi[/bold cyan]", border_style="cyan"))
    url = Prompt.ask("[yellow]URL[/yellow]").strip()
    if not url.startswith('http'):
        url = 'https://' + url

    parsed = urlparse(url)
    domain = parsed.netloc

    table = Table(box=box.SIMPLE, border_style="cyan", header_style="bold cyan")
    table.add_column("Yoxlama", style="yellow", min_width=22)
    table.add_column("Nəticə", style="white")

    table.add_row("Domain", domain)
    table.add_row("Protokol", parsed.scheme.upper())
    table.add_row("Yol", parsed.path or "/")

    # Suspicious patterns
    suspicious = []
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        suspicious.append("IP ünvanı URL-də")
    if len(domain) > 50:
        suspicious.append("Çox uzun domain")
    if domain.count('.') > 4:
        suspicious.append("Çox alt-domain")
    if any(w in domain.lower() for w in ['secure','login','verify','account','update','bank','paypal']):
        suspicious.append("Şübhəli açar söz")
    if re.search(r'[0-9]', domain.split('.')[0]):
        suspicious.append("Domendə rəqəm var")

    risk = "🔴 YÜKSƏK" if len(suspicious)>=2 else "🟡 ORTA" if suspicious else "🟢 AŞAĞI"
    table.add_row("Risk Səviyyəsi", risk)
    table.add_row("Şübhəli Nişanlar", '\n'.join(suspicious) if suspicious else "Tapılmadı")

    # HTTP check
    try:
        r = requests.get(url, timeout=6, allow_redirects=True)
        table.add_row("HTTP Status", str(r.status_code))
        table.add_row("Final URL", r.url)
        table.add_row("Server", r.headers.get('Server','?'))
        table.add_row("Content-Type", r.headers.get('Content-Type','?'))
        if r.url != url:
            table.add_row("⚠ Redirect", f"{url} → {r.url}")
    except Exception as e:
        table.add_row("Bağlantı", f"[red]{e}[/red]")

    console.print(table)
    back_prompt()

# ── 8. Password ────────────────────────────────────────────────────────────
def password():
    console.print(Panel("[bold cyan]🔑 Şifrə Güc Analizi[/bold cyan]", border_style="cyan"))
    import getpass
    pw = getpass.getpass("Şifrə (görünməyəcək): ")

    score = 0
    checks = []

    if len(pw) >= 8:  score+=1; checks.append(("✓ Uzunluq ≥8", True))
    else: checks.append(("✗ Uzunluq <8", False))

    if len(pw) >= 12: score+=1; checks.append(("✓ Uzunluq ≥12", True))
    else: checks.append(("✗ Uzunluq <12", False))

    if re.search(r'[A-Z]', pw): score+=1; checks.append(("✓ Böyük hərf", True))
    else: checks.append(("✗ Böyük hərf yoxdur", False))

    if re.search(r'[a-z]', pw): score+=1; checks.append(("✓ Kiçik hərf", True))
    else: checks.append(("✗ Kiçik hərf yoxdur", False))

    if re.search(r'\d', pw): score+=1; checks.append(("✓ Rəqəm", True))
    else: checks.append(("✗ Rəqəm yoxdur", False))

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', pw): score+=1; checks.append(("✓ Xüsusi simvol", True))
    else: checks.append(("✗ Xüsusi simvol yoxdur", False))

    common = ['password','123456','qwerty','admin','letmein','welcome','monkey']
    if pw.lower() not in common: score+=1; checks.append(("✓ Ümumi şifrə deyil", True))
    else: checks.append(("✗ Çox yaygın şifrə!", False))

    levels = {7:"🟢 ƏLAMƏTDAR", 5:"🟡 YAXŞI", 3:"🟠 ORTA", 0:"🔴 ZƏIF"}
    level = next(v for k,v in sorted(levels.items(),reverse=True) if score>=k)

    table = Table(box=box.SIMPLE, border_style="cyan", header_style="bold cyan")
    table.add_column("Yoxlama", style="white", min_width=26)
    table.add_column("Status", width=8)

    for text, ok in checks:
        table.add_row(text, "✓" if ok else "✗", style="green" if ok else "red")

    console.print(table)
    console.print(f"\n[bold]Ümumi Bal: {score}/7  —  {level}[/bold]")

    # Crack time estimate
    charset = 0
    if re.search(r'[a-z]',pw): charset+=26
    if re.search(r'[A-Z]',pw): charset+=26
    if re.search(r'\d',pw): charset+=10
    if re.search(r'[^a-zA-Z\d]',pw): charset+=32
    if charset > 0:
        combos = charset**len(pw)
        secs = combos / 1e10
        if secs < 60: t = f"{secs:.1f} saniyə"
        elif secs < 3600: t = f"{secs/60:.1f} dəqiqə"
        elif secs < 86400: t = f"{secs/3600:.1f} saat"
        elif secs < 31536000: t = f"{secs/86400:.0f} gün"
        else: t = f"{secs/31536000:.0f} il"
        console.print(f"[cyan]Brute-force qiymət:[/cyan] ~{t} (10B cəhd/san)")

    back_prompt()

# ── 9. Email ───────────────────────────────────────────────────────────────
def email():
    console.print(Panel("[bold cyan]📧 Email Analizi[/bold cyan]", border_style="cyan"))
    addr = Prompt.ask("[yellow]Email ünvanı[/yellow]").strip()

    valid = bool(re.match(r'^[^@]+@[^@]+\.[^@]+$', addr))
    domain = addr.split('@')[-1] if '@' in addr else ''

    table = Table(box=box.SIMPLE, border_style="cyan", header_style="bold cyan")
    table.add_column("Alan", style="yellow", min_width=20)
    table.add_column("Dəyər", style="white")

    table.add_row("Email", addr)
    table.add_row("Format", "✓ Düzgün" if valid else "✗ Yanlış format")
    table.add_row("Domain", domain)

    if domain:
        try:
            ip = socket.gethostbyname(domain)
            table.add_row("Domain IP", ip)
        except:
            table.add_row("Domain IP", "[red]Tapılmadı[/red]")

        # MX lookup via DNS
        try:
            import subprocess
            result = subprocess.run(['nslookup','-type=MX',domain],
                                  capture_output=True, text=True, timeout=5)
            mx_lines = [l for l in result.stdout.split('\n') if 'mail exchanger' in l.lower() or 'MX' in l]
            table.add_row("MX Qeydi", mx_lines[0].strip() if mx_lines else "Tapılmadı")
        except:
            table.add_row("MX Qeydi", "Yoxlanıla bilmədi")

        # Known providers
        providers = {
            'gmail.com':'Google Gmail','yahoo.com':'Yahoo Mail',
            'outlook.com':'Microsoft Outlook','hotmail.com':'Microsoft Hotmail',
            'protonmail.com':'ProtonMail','icloud.com':'Apple iCloud',
            'mail.ru':'Mail.ru','yandex.com':'Yandex Mail',
        }
        prov = providers.get(domain.lower(), "Naməlum / Şəxsi domain")
        table.add_row("Provayder", prov)
        table.add_row("Disposable?", "⚠ Bəli" if any(x in domain for x in ['temp','throw','fake','guerrilla','mailinator']) else "Yox")

    console.print(table)
    back_prompt()

# ── 10. SSL ────────────────────────────────────────────────────────────────
def ssl_check():
    console.print(Panel("[bold cyan]🔒 SSL Sertifikat Yoxlayıcı[/bold cyan]", border_style="cyan"))
    host = Prompt.ask("[yellow]Domain (məs: google.com)[/yellow]").strip()
    host = host.replace('https://','').replace('http://','').split('/')[0]

    def run():
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(8)
        conn.connect((host, 443))
        cert = conn.getpeercert()
        conn.close()
        return cert

    try:
        cert = with_spinner("SSL yoxlanılır", run)

        table = Table(box=box.SIMPLE, border_style="cyan", header_style="bold cyan")
        table.add_column("Alan", style="yellow", min_width=22)
        table.add_column("Dəyər", style="white")

        subj = dict(x[0] for x in cert.get('subject',[]))
        issuer = dict(x[0] for x in cert.get('issuer',[]))

        table.add_row("Domain", host)
        table.add_row("Sahibi (CN)", subj.get('commonName','?'))
        table.add_row("Orqanizasiya", subj.get('organizationName','?'))
        table.add_row("Verən (Issuer)", issuer.get('organizationName','?'))
        table.add_row("Verən CN", issuer.get('commonName','?'))

        not_after = cert.get('notAfter','')
        if not_after:
            exp = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            days_left = (exp - datetime.utcnow()).days
            color = "green" if days_left > 30 else "red"
            table.add_row("Bitmə tarixi", f"[{color}]{exp.strftime('%d.%m.%Y')} ({days_left} gün qalıb)[/{color}]")

        not_before = cert.get('notBefore','')
        if not_before:
            start = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
            table.add_row("Başlama tarixi", start.strftime('%d.%m.%Y'))

        sans = cert.get('subjectAltName',[])
        if sans:
            san_list = ', '.join(v for t,v in sans[:5])
            table.add_row("Alt adlar (SAN)", san_list)

        ver = cert.get('version',0)
        table.add_row("SSL Versiya", f"TLS v{ver}")
        table.add_row("Status", "[green]✓ Etibarlı[/green]")

        console.print(table)

    except ssl.SSLCertVerificationError:
        console.print("[red]⚠ SSL sertifikat etibarsızdır![/red]")
    except Exception as e:
        console.print(f"[red]Xəta: {e}[/red]")

    back_prompt()

# ── 11. Social Media ───────────────────────────────────────────────────────
def social():
    console.print(Panel("[bold cyan]📱 Sosial Media Analizi[/bold cyan]", border_style="cyan"))
    uname = Prompt.ask("[yellow]İstifadəçi adı[/yellow]").strip()

    platforms = {
        "GitHub":    (f"https://api.github.com/users/{uname}", "github"),
        "Reddit":    (f"https://www.reddit.com/user/{uname}/about.json", "reddit"),
    }

    table = Table(box=box.SIMPLE, border_style="cyan", header_style="bold cyan")
    table.add_column("Platform", style="yellow", min_width=12)
    table.add_column("Alan", style="cyan", min_width=18)
    table.add_column("Dəyər", style="white")

    headers = {'User-Agent':'Asplaude-OSINT/1.0'}

    for plat, (url, ptype) in platforms.items():
        try:
            r = requests.get(url, headers=headers, timeout=6)
            if r.status_code != 200:
                table.add_row(plat, "Status", f"HTTP {r.status_code}")
                continue
            d = r.json()
            if ptype == "github":
                fields = [
                    ("Ad", d.get('name') or '?'),
                    ("Bio", (d.get('bio') or '?')[:60]),
                    ("Yer", d.get('location') or '?'),
                    ("Şirkət", d.get('company') or '?'),
                    ("Repo", str(d.get('public_repos','?'))),
                    ("Follower", str(d.get('followers','?'))),
                    ("Qoşulma", d.get('created_at','?')[:10]),
                    ("Profil", d.get('html_url','?')),
                ]
            elif ptype == "reddit":
                dd = d.get('data',{})
                fields = [
                    ("Ad", dd.get('name','?')),
                    ("Karma", str(dd.get('total_karma','?'))),
                    ("Post Karma", str(dd.get('link_karma','?'))),
                    ("Comment Karma", str(dd.get('comment_karma','?'))),
                    ("Qoşulma", datetime.utcfromtimestamp(dd.get('created_utc',0)).strftime('%d.%m.%Y') if dd.get('created_utc') else '?'),
                    ("Premium", "Bəli" if dd.get('is_gold') else "Xeyr"),
                ]
            else:
                fields = [("Status","Tapıldı")]

            for k,v in fields:
                table.add_row(plat, k, str(v)[:80])
            table.add_row("","","")
        except Exception as e:
            table.add_row(plat, "Xəta", str(e)[:50])

    console.print(table)
    back_prompt()

# ── 12. QR ─────────────────────────────────────────────────────────────────
def qr():
    console.print(Panel("[bold cyan]📷 QR Kod Oxuyucu / Yaradan[/bold cyan]", border_style="cyan"))
    choice = Prompt.ask("[yellow][1] QR Yarat  [2] QR Oxu\nSeçim[/yellow]", default="1")

    if choice == "1":
        text = Prompt.ask("[yellow]Mətn və ya URL[/yellow]")
        path = Prompt.ask("[yellow]Saxla (fayl adı, məs: qr.png)[/yellow]", default="qr.png")
        try:
            img = qrcode.make(text)
            img.save(path)
            console.print(f"\n[bold green]✓ QR kod yaradıldı:[/bold green] {os.path.abspath(path)}")
            console.print(f"[cyan]Məzmun:[/cyan] {text}")
            console.print(f"[cyan]Ölçü:[/cyan] {img.size[0]}x{img.size[1]} px")
        except Exception as e:
            console.print(f"[red]Xəta: {e}[/red]")
    else:
        if not QR_READ:
            console.print("[yellow]⚠ pyzbar quraşdırılmayıb. 'pip install pyzbar' edin.[/yellow]")
            console.print("[dim]Linux: sudo apt install libzbar0[/dim]")
            back_prompt(); return
        path = Prompt.ask("[yellow]QR şəkil yolu[/yellow]").strip().strip('"')
        try:
            img = Image.open(path)
            decoded = qr_decode(img)
            if decoded:
                for d in decoded:
                    console.print(f"\n[bold green]✓ QR oxundu![/bold green]")
                    console.print(f"[cyan]Məzmun:[/cyan] {d.data.decode('utf-8','ignore')}")
                    console.print(f"[cyan]Növ:[/cyan] {d.type}")
            else:
                console.print("[yellow]QR kod tapılmadı[/yellow]")
        except Exception as e:
            console.print(f"[red]Xəta: {e}[/red]")

    back_prompt()

# ── MAIN ───────────────────────────────────────────────────────────────────
HANDLERS = {
    "exif": exif, "ip_domain": ip_domain, "username": username,
    "breach": breach, "arp": arp, "hash_tool": hash_tool,
    "url_check": url_check, "password": password, "email": email,
    "ssl_check": ssl_check, "social": social, "qr": qr,
}

def main():
    while True:
        clear()
        show_banner()
        show_menu()

        choice = Prompt.ask("[bold yellow]Seçim[/bold yellow]").strip()

        if choice == "0":
            console.print("\n[bold cyan]Asplaude OSINT — Görüşənədək! 👋[/bold cyan]\n")
            break

        handler = next((fn for num,_,_,fn in MENU_ITEMS if num==choice), None)
        if handler and handler != "exit":
            clear()
            show_banner()
            HANDLERS[handler]()
        else:
            console.print("[red]Yanlış seçim![/red]")
            time.sleep(1)

if __name__ == "__main__":
    main()
