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

cd Asplaude

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

python asplaude_osint.py

