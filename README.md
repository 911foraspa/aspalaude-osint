# aspalaude-osint
# Fedora/Linux
sudo dnf install python3 python3-pip python3-devel gcc libpcap-devel libzbar libzbar-devel -y

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

python3 asplaude_osint.py

# Windows 
- Python lazimdir(3.10+ önerilir)
# https://www.python.org/downloads/

cd aspaulade-osint

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

python asplaude_osint.py

# For termux
- warning: arpscan and qrcode dont work good in termux

pkg update && pkg upgrade -y
pkg install iproute2

pkg install python git clang make libffi openssl rust -y

pip install --upgrade pip

git clone https://github.com/911foraspa/aspalaude-osint
cd aspalaude-osint

pip install -r requirements.txt

<h2 align="center">Gorunum</h2>

<p align="center">
  <img src="https://i.hizliresim.com/mqlpjn2.png" width="700"/>
</p>






