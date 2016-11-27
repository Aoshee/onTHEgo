#!/usr/bin/env python
import cmd
import os
# random banner
import random
# import onTHEgo
from onTHEgo import mainLib
# from onTHEgo.mainLib import *
W = '\033[0m'
LP = '\033[1;35m'
# banner1
banners = ['banner1', 'banner2']
choice = random.choice(banners)
if(choice == 'banner1'):
	mainLib.banner1()
else:
	mainLib.banner2()
mainLib.main_menu()
class MainShell(cmd.Cmd):
    prompt = LP + '[onTHEgo]:~$ ' + W
    def do_help(self, line):
        mainLib.help_menu()
    def do_exit(self, line):
        exit(1)
    def do_clear(self, line):
        os.system("clear")
    def do_recon(self, line):
        mainLib.recon()
    def do_smtp(self, line):
	mainLib.smtp()
    def do_http(self, line):
	mainLib.http()
    def do_wifi(self, line):
	mainLib.wifi()
    def do_networking(self, line):
	mainLib.networking()
    def do_EOF(self, line):
        exit(1)
if __name__ == "__main__":
    MainShell().cmdloop()

