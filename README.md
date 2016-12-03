# onTHEgo: mobile pentest framework
## What is onTHEgo?
Like the title says, it's a mobile pentest framework written for Linux and Android. It includes recon modules, smtp modules, http modules, wireless modules, and network modules. It allows you to due a full scale attack right from a rooted Android phone/Linux desktop. The tool is protected by the MIT license (READ LICENSE FOR FULL DETAILS) so it can be edited and redistributed with proper credit. If you have an issue with the tool or there is a bug, feel free to put an issue request in to get it fixed. To contact me, go to [this]('https://r3c0nx00.github.io/contact.html') site to contact me.
## How to use the tool
To be able to run this tool, you will need the required modules in the REQUIREMENTS file. To install them the easy way type:
```bash
sudo pip install -r REQUIREMENTS
```
This will install all modules that are listed in file to prevent you from entering them in one by one. The next step is easy just run:
```bash
sudo python onTHEgo.py
```
And this will run the tool. Now you have it running, let's show off some of its' cool features.
## Features
### Recon
* Shodan
	* Requires API key (free or unlimited)
* iplocate
* hostseek
	* Captures ARP packets on network to show hosts (with Vendor identification)

### SMTP modules
* emailbombing
	* Easy to use (might want a throw away account)
* smsbombing
	* Requires Twilio account

### HTTP modules
* webcrawler
	* crawl websites for external links (a href tags)

### Wireless modules
* wifidiscover (coming soon)
	* discover nearby access points and view the security they are using
* wificracker (coming soon)
	* crack wireless access point passwords 

### Network modules
I actually do not have any network modules, but I might add a packet manipulation module.

## Summary
onTHEgo is a versitile hacking platform for penetration testers and security reseachers alike. Enjoy the tool and make sure to check out the site for the development of onTHEgo (coming soon) and check out my personal website to learn more about who I am and ways to contact me.
