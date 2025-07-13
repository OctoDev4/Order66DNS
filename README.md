# Order66DNS
 
# 🛰️ Order66DNS – DNS Spoofing from the Dark Side

![Order66DNS](https://github.com/user-attachments/assets/91ea02de-c6c2-42b8-b184-eeae8b8c5f32)

Order66DNS is a Python-based DNS spoofing tool built with Scapy and NetfilterQueue. It intercepts DNS requests and sends forged responses to redirect victims to a fake IP of your choice.

Inspired by the execution power of Order 66, this tool hijacks domain resolution in real-time, forcing the target to trust an Imperial redirection.

---

## ⚙️ Requirements

- Python 3.6+
- Linux with iptables and root permissions

### Python dependencies:

```bash
pip install scapy netfilterqueue

```
NetfilterQueue system support:
 ```bash
sudo apt install libnetfilter-queue-dev
```

📦 Installation
Clone the repository:
```bash
git clone https://github.com/OctoDev4/Order66DNS.git
cd Order66DNS
```
(Optional) Make the script executable:
```bash
chmod +x main.py
```
🚀 Usage
Run the script with:
```bash
sudo python3 main.py -t example.com -i 1.1.1.1
```
-t: The target domain to spoof (e.g., stackoverflow.com)

-i: The spoofed IP you want to redirect the victim to


🔧 IPTABLES Setup
Before running the script, use iptables to redirect DNS packets to NetfilterQueue:

For MITM in forwarded traffic (e.g., over a bridge or AP):
```bash
sudo iptables --flush
sudo iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num
```
For testing on your own machine:
```bash
sudo iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
sudo iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0
```
🧹 Cleanup
After testing, reset your iptables rules:
```bash
sudo iptables --flush
```

Use Order66DNS wisely — may the Force be with you, always.
