#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__      = 'Christophoros Petrou (chrispetrou)'
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

import socket
from colorama import Fore,Back,Style
from argparse import ArgumentTypeError
try:
    import validators
except ImportError, error:
    print '\n[!] Please install missing modules!\n'
    sys.exit(0)


def validatePort(port):
    if isinstance(int(port), (int, long)):
        if 1 < int(port) < 65536:
            return int(port)
    else:
        print '{}[x] Port must be in range 1-65535{}'.format(FR,F)
        sys.exit(0)


def validateIP(ip):
    try:
        if socket.inet_aton(ip):
            return ip
    except socket.error:
        print '{}[x] Invalid ip provided{}'.format(FR,S)
        sys.exit(0)


def ValidateUrl(url):
    if validators.url(url):
        return url
    else: raise ArgumentTypeError('{}~~> Invalid url{}'.format(RD, S))

