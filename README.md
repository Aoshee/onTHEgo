# onTHEgo
onTHEgo is a mobile penetration testing tool that can be run on rooted Android phones with a terminal emulator, git, and python. The tool is designed to be lightweight and easy to use.

## Requirements
You will need scapy. 
```bash
sudo pip install -r REQUIREMENTS
```
## Usage
It's simple, when you start up the tool, you get a thing that looks like this:

============================================
######onTHEgo mobile pentest framework        
============================================
1. Host info (1 #url)
2. Wifi Sniffer (2 #interface name)
3. MITM Attack
4. TCP SYN/ACK flood
5. Undecided
6. Exit

otg>

Pretty simple, right? So it breaks down like this:
* If you wanna get the IP of a website, do this: 1 example.com
* Next, if you wanna sniff Wireless access points and get MAC addresses, you need to prep it.
First, you need to put your wireless card/device in monitor mode with airmon-ng:
```bash
sudo airmon-ng start #interface name
```
After that, just switch tabs back to the tool and do (example): 2 wlp3s0mon # mon means monitor.
When you're done with the scan, put your wireless card/device out of monitor mode doing this:
```bash
sudo airmon-ng stop #interface name ending in mon (wlp3s0mon)
```
* MITM (or Man in The Middle) allows you ARP poison a target and sniff traffic. All you need is: the target IP, the interface name (non monitoring), and the router IP.
* TCP SYN/ACk flood (or DoS) allows you to flood a target with TCP SYN/ACK packages (SYN = sync, ACK = acknowlege). The tool will notify when the target stops acknowledging the SYN (also known as the Three-Way handshake = TCP SYN/ACK).
* The undecided one might be a slot for drone hacking or something else visit [this](r3c0nx00.github.io/contact.html) and contact me on any of those to give me some ideas to roll into the mobile framework.

That's it for the documentation, I hope you enjoy the tool and keep on hacking!   
