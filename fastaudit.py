#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__      = 'chrispetrou'
__description__ = 'FastAudit: A Wordpress security auditor!'
__testsite__    = 'http://localhost:8888/wptest/' # local
__thanks_to__   = 'WPScan team for the amazing API'

"""
╔════════════════════ Description ═════════════════════╗
║ FastAudit - A WordPress security auditor!            ║
║ author: Christophoros Petrou (chrispetrou)           ║
║ Copyright (C) 2018                                   ║
║                                                      ║
║ This tool scans a wordpress site for various         ║
║ vulnerabilities. It can extract usernames,           ║
║ plugins and the theme used and then it makes use of  ║
║ the 'WPScan Vulnerability Database' to recognise     ║
║ potential vulnerabilities. It also uses shodan and   ║
║ checks for potential weak/pwned usernames, passwords.║
╚════════════════════════ End ═════════════════════════╝
"""

import sys, os
import ConfigParser
from wp.utils import FastAudit
from colorama import Fore,Back,Style
from argparse import ArgumentParser, ArgumentTypeError, RawTextHelpFormatter
try:
    import validators
except ImportError, error:
    print '\n[!] Please install missing modules!\n'
    sys.exit(0)

# console colors
B, S, F  = Style.BRIGHT, Style.RESET_ALL, Fore.RESET
G, RD, Y, R, BR, C  = Fore.GREEN, Fore.RED, Fore.YELLOW, Back.RED, Back.RESET, Fore.CYAN


def banner():
    print "\n╔═══╗     ╔╗        ╔╗╔╗ "
    print   "║╔══╝    ╔╝╚╗       ║╠╝╚╗"
    print   "║╚══╦══╦═╩╗╔╬══╦╗╔╦═╝╠╗╔╝"
    print   "║╔══╣╔╗║══╣║║╔╗║║║║╔╗╠╣║ "
    print   "║║  ║╔╗╠══║╚╣╔╗║╚╝║╚╝║║╚╗"
    print   "╚╝  ╚╝╚╩══╩═╩╝╚╩══╩══╩╩═╝...(ver. {}1.4{})".format(RD, S)

def console():
    """argument parser"""
    parser = ArgumentParser(description="{}FastAudit:{} A wordpress security auditor!".format(B+G, S),formatter_class=RawTextHelpFormatter)
    parser._optionals.title = "{}arguments{}".format(B, S)
    parser.add_argument('-u', "--url", help='Specify a url to scan', type=ValidateUrl, metavar='')
    parser.add_argument('-eu', "--enumusers", help="Enumerate Users [{0}Default:{2} {1}False{2}]".format(B, RD, S), action='store_true')
    parser.add_argument('-ep', "--enumplugins", help="Enumeate plugins [{0}Default:{2} {1}False{2}]".format(B, RD, S), action='store_true')
    parser.add_argument('-ua', "--useragent", help="Use a random user-agent [{0}Default:{2} {1}FastAudit_Agent{2}]".format(B, G, S), action='store_true')
    parser.add_argument('-p', "--proxy", help="Use a proxy (settings: config.cfg) [{0}Default:{1} {2}burp settings{1}]".format(B, S, G), action='store_true')
    parser.add_argument('-s', "--save", help="Save the results [{0}Default:{2} {1}False{2}]".format(B, RD, S), action='store_true')
    parser.add_argument("--shodan", help="Use shodan api [{0}Default:{2} {1}False{2}]".format(B, RD, S), action='store_true')
    parser.add_argument("--sha1", help="Specify a password (in sha1) to check for security issues", metavar='')
    return parser.parse_args()


def ValidateUrl(url):
    if validators.url(url):
        return url
    else: raise ArgumentTypeError('{}~~> Invalid url{}'.format(RD, S))


if __name__ == '__main__':
    os.system('clear')
    banner()
    args = console()

    config = ConfigParser.RawConfigParser(allow_no_value=True)
    config.readfp(open('config.cfg'))
    
    sh_key = config.has_option('shodan-key','key') and config.get('shodan-key','key') or None
    host = config.has_option('proxy-settings','host') and config.get('proxy-settings','host') or None
    port = config.has_option('proxy-settings','port') and config.get('proxy-settings','port') or None

    if args.url:
        if args.proxy:
            if (host or port) is None:
                print "\n{}[x] Proxy error: host and/or port NOT set.{}\n".format(R, BR)
                sys.exit(0)
            else: 
                print '\n{0}[*]{1} Proxy: {0}{2}ON{1}'.format(B, S, G)
        else:
            print '\n{0}[*]{1} Proxy: {0}{2}OFF{1}'.format(B, S, RD)
        
        if args.enumusers: print '{0}[*]{1} Enumerate users: {0}{2}ON{1}'.format(B, S, G)
        else: print '{0}[*]{1} Enumerate users: {0}{2}OFF{1}'.format(B, S, RD)

        if args.enumplugins: print '{0}[*]{1} Enumerate plugins: {0}{2}ON{1}'.format(B, S, G)
        else: print '{0}[*]{1} Enumerate plugins: {0}{2}OFF{1}'.format(B, S, RD)
        print ''
        try:
            FastAudit(args.url, args.proxy, host, port, args.sha1, args.save, args.enumusers, args.enumplugins, args.shodan, sh_key, args.useragent)
        except KeyboardInterrupt:
            print '\n{}[+] Exiting!{}\n'.format(R, BR)
            sys.exit(0)
    else: print '{}usage:{} fastaudit.py [-h] [-u] [-eu] [-ep] [-ua] [-p] [-s] [--shodan] [--sha1]'.format(B, S)
#_EOF