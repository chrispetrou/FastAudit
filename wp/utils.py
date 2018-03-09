#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__      = 'chrispetrou'
__description__ = 'FastAudit: A Wordpress security auditor!'
__testsite__    = 'http://localhost:8888/wptest/' # local
__thanks_to__   = 'WPScan team for the amazing API'

"""
##==-=-=-=-=-=-=-=-=-= Description =-=-=-=-=-=-=-=-==###
# FastAudit - A WordPress security auditor!            #
# author: chrispetrou                                  #
# Copyright (C) 2018                                   #
#                                                      #
# This tool scans a wordpress site for various         #
# vulnerabilities. It can extract usernames,           #
# plugins and the theme used and then it makes use of  #
# the 'WPScan Vulnerability Database' to recognise     #
# potential vulnerabilities. It also uses shodan and   #
# checks for potential weak/pwned usernames, passwords.#
##==-=-=-=-=-=-=-=-=-=-=-= End =-=-=-=-=-=-=-=-=-=-==###
"""

import sys, re
reload(sys)
sys.setdefaultencoding('utf8')
import time
import shodan
import logging
import requests
from socket import *
from urlparse import urlparse
from bs4 import BeautifulSoup
try:
    from tabulate import tabulate
    from fake_useragent import UserAgent
    from colorama import Fore,Back,Style
except ImportError, error:
    print '\n[!] Please install missing modules!\n'
    sys.exit(0)

# console colors
B, S, F  = Style.BRIGHT, Style.RESET_ALL, Fore.RESET
G, RD, Y, R, BR, C  = Fore.GREEN, Fore.RED, Fore.YELLOW, Back.RED, Back.RESET, Fore.CYAN

class FastAudit():

    def __init__(self, url, proxy=False, host=None, port=None, sha1pass=None, save=False, enumUsrs=False, enumPlgs=False, shodan_api=False, shodan_key=None, useragent=False):
        self.__url       = url
        self.__proxy     = proxy
        self.__host      = host
        self.__port      = port
        self.__save      = save
        self.__pass      = sha1pass
        self.__shodan    = shodan_api
        self.__key       = shodan_key

        # set user-agent
        if useragent:
            self.__useragent = self.genUA()
        else:
            self.__useragent = 'FastAudit_Agent'

        # if specified create a log file to save the results
        if self.__save:
            logging.basicConfig(filename='{}{}'.format(self.getNetloc(self.__url).split()[0], '.log'), format='%(asctime)s %(message)s')

        self.__content   = self.getContent()
        self.__links     = self.getLinks(self.__content)

        # basic/default enumeration
        self.__wpver = self.wpVersion()
        if self.__wpver:
            self.wpverVulns()
        
        self.__theme = self.wpTheme()
        if self.__theme:
            self.themeVulns()

        # optional/more-advanced enumeration
        if enumUsrs:
            self.__usernames = self.enumUsers()
            self.showUsers()

        if enumPlgs:
            self.__plugins = self.enumPlugins()
            if self.__plugins:
                self.pluginVulns()

        if self.__pass:
            self.pwnedPass()

        if self.__shodan and self.__key:
            self.shodanSearch(self.__url)


    def showUsers(self):
        """print usernames gathered using tabulate"""
        if self.__save:
            logging.warning('{} usernames found.'.format(len(self.__usernames)))
            if len(self.__usernames)>0:
                for username in self.__usernames: 
                    logging.warning(username)
        print '\n{0}[+]{1} {0}{2}{3}{1} usernames found!'.format(B, S, G, len(self.__usernames))
        if len(self.__usernames)>0:
            print tabulate([[uname] for uname in self.__usernames], headers=["{}Usernames{}".format(B+G, S)], tablefmt="fancy_grid")

    def ret(self, t=.1):
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")
        time.sleep(t)


    def getNetloc(self, url):
        """returns the base url"""
        return urlparse(url).netloc


    def genUA(self):
        """returns a fake random user-agent"""
        return str(UserAgent().random)


    def _http_req(self, url, useragent=None):
        """a custom http-request function"""
        if useragent is None:
            useragent = self.__useragent
        try:
            # check for proxy
            if self.__proxy and self.__host and self.__port:
                proxies = {"http":'{}:{}'.format(self.__host, self.__port), "https":'{}:{}'.format(self.__host, self.__port)}
                return requests.get(url, proxies=proxies, verify=False, headers = {'User-Agent':useragent})
            else:
                return requests.get(url, headers = {'User-Agent':useragent})

        except requests.exceptions.ProxyError:
            print '{}[x] A proxy error occured!{}\n'.format(R, S)
            sys.exit(0)
        except requests.exceptions.TooManyRedirects:
            print '{}[x] Too many redirects!{}\n'.format(R, S)
            sys.exit(0)
        except requests.exceptions.Timeout:
            print '{}[x] The request timed out!{}\n'.format(R, S)
            sys.exit(0)
        except requests.exceptions.SSLError:
            print '{}[x] An SSL error occured!{}\n'.format(R, S)
            sys.exit(0)
        except requests.exceptions.ConnectionError:
            print '{}[x] A connection error occured!{}\n'.format(R, S)
            sys.exit(0)


    def resolve(self, domain):
        """domain2ip"""
        try:
            return gethostbyname(self.getNetloc(domain))
        except gaierror:
            return None
    
    
    def getService(self, port):
        """returns service by port"""
        try:
            return getservbyport(port)
        except socket.error:
            return 'Unknown service'


    def getContent(self):
        """returns basic/main content"""
        if self.__save:
            logging.warning('Retrieving page main content.')
        return self._http_req(self.__url).text     


    def getLinks(self, content):
        """extract the links of the page"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            links = soup.findAll(name='link')
            return list(set(link.get('href') for link in links if link.has_attr("href")))
        except Exception, error:
            raise error


    def wpVersion(self):
        """returns wordpress version"""
        try:
            soup = BeautifulSoup(self.__content, 'html.parser')
            ver = soup.find(attrs={"name":"generator"})['content']
            print '{0}[{2} WP version {1}{0}]{1} {0}{3}{1}'.format(B, S, G, ver)
            if self.__save:
                logging.warning('Wordpress version detected: {}'.format(ver))
            return ver
        except TypeError:
            return None


    def wpTheme(self):
        """returns wordpress theme"""
        # reference: https://codeable.io/find-out-what-theme-plugins-wordpress/
        theme = re.compile(r'wp-content/themes/(.*?)/')
        try:
            th = theme.search(self.__content).group(1)
            print '\n{0}[{2} Theme {1}{0}]{1} {0}{3}{1}'.format(B, S, G, th)
            if self.__save:
                logging.warning('Wordpress theme detected: {}'.format(th))
            return th
        except AttributeError:
            return None

    def enumPlugins(self):
        """extracts plugins output: {plugin:version}"""
        try:
            ver = re.compile(r'/?ver=([0-9]*\.?[0-9]*)')
            # reference: https://winningwp.com/how-to-tell-which-plugins-a-website-uses/
            plugin, plugins = re.compile(r'wp-content/plugins/(.*?)/'), {}
            for link in self.__links:
                if "wp-content/plugins" in link:
                    if '?ver' in link: # search if version is available
                        plugins[plugin.search(link).group(1)] = ver.search(link).group(1)
                    else:
                        plugins[plugin.search(link).group(1)] = 'Unknown'
            return plugins
        except Exception, error:
            raise error


    def printInfo(self, vulns, key, value):
        print '{0}╚══[{2}x{3}]{1}{0} Possible vulnerabilities:{1}'.format(B, S, RD, F)
        for vuln in vulns:
            if 'title' in vuln:
                print '\n• {0}{2}{1}'.format(RD, S, vuln['title'])
                if self.__save:
                    logging.warning('Wordpress {} ({}) possible vulnerability detected: {}'.format(key, value, vuln['title']))
            if 'vuln_type' in vuln:
                print '  {0}╚══[Vulnerability-type]{1} {2}{3}{1}'.format(B, S, RD, vuln['vuln_type'])
            if 'fixed_in' in vuln:
                print '  {0}╚══[Fixed]{1} Fixed in verion {2}{3}{1}'.format(B, S, RD, vuln['fixed_in']) 
            if 'references' in vuln:
                if 'url' in vuln['references']:
                    print '  {}╚══[References]:{}'.format(B, S)
                    for u in vuln['references']['url']:
                        print '\t╚══> {}'.format(u)


    def wpverVulns(self):
        """returns vulns based on version"""
        try:    
            if self.__wpver:
                ans = self._http_req('https://wpvulndb.com/api/v2/wordpresses/{}'.format(self.__wpver.split()[1].replace('.','')))
                if ans.status_code == 200:
                    vulns = ans.json()[self.__wpver.split()[1]]['vulnerabilities']
                    if vulns:
                        self.printInfo(vulns, 'version', self.__wpver)
                    else: print '{0}╚══{2}[+]{1} No vulnerabilities found for {3}{4}{1}'.format(B, S, G, C, self.__wpver)
                else: print '{0}╚══{2}[+]{1} No vulnerabilities found for {3}{4}{1}'.format(B, S, G, C, self.__wpver)
        except KeyError:
            pass
        except IndexError:
            pass
        except Exception, error:
            print '{}{}{}'.format(RD, error, S)


    def themeVulns(self):
        """vulnerabilities based on the theme used"""
        try:
            if self.__theme:
                ans = self._http_req('https://wpvulndb.com/api/v2/themes/{}'.format(self.__theme))
                if ans.status_code == 200:
                    vulns = ans.json()[self.__theme.lower()]['vulnerabilities']
                    if vulns:
                        self.printInfo(vulns, 'theme', self.__theme)
                    else: print '{0}╚══{2}[+]{1} No vulnerabilities found for {3}{4}{1}'.format(B, S, G, C, self.__theme)
                else: print '{0}╚══{2}[+]{1} No vulnerabilities found for {3}{4}{1}'.format(B, S, G, C, self.__theme)
        except KeyError:
            pass
        except Exception, error:
            print '{}{}{}'.format(RD, error, S)


    def pluginVulns(self):
        """makes use of wpscan API and searches for vulns"""
        try:
            for plugin, version in self.__plugins.items():
                print '\n[{0}Plugin{1}] {2}{3}{1} (ver. {2}{4}{1})'.format(B+C, S, C, plugin, version)
                ans = self._http_req('https://wpvulndb.com/api/v2/plugins/{}'.format(plugin))
                if ans.status_code == 200:
                    vulns = ans.json()[plugin]['vulnerabilities']
                    if vulns:
                        self.printInfo(vulns, 'plugin', plugin)
                    else: print '{0}╚══{2}[+]{1} No vulnerabilities found!'.format(B, S, G)
                else: print '{0}╚══{2}[+]{1} No vulnerabilities found!'.format(B, S, G)
        except Exception, ApiError:
            raise ApiError


    def extractUsers(self, links):
        """returns a list of users"""
        user, users = re.compile(r'author/(.*?)/'), []
        try:
            for link in links:
                if "author" in link:
                    users.append(user.search(link).group(1))
        except AttributeError:
            pass
        return list(set(users))


    def enumUsers(self):
        """enumerates users based on the old author-id dork"""
        id = 1
        users = []
        while True:
            newUrl= '{}?author={}'.format(self.__url, id)
            ans = self._http_req(newUrl)
            if ans.status_code == 200:
                users += self.extractUsers(self.getLinks(ans.text))
                id += 1
            elif ans.status_code == 404:
                break
            else:
                print '[{}] {}'.format(ans.status_code, ans.reason)
        return users


    def pwnedPass(self):
        """checks if password(sha1) has been used before"""
        print '\n{}[*]{} Checking if password has been used/breeched before...'.format(B, S)
        url = 'https://api.pwnedpasswords.com/pwnedpassword/{}'.format(self.__pass)
        if self.__save:
            logging.warning('Using FastAudit_Agent as user-agent for haveibeenpwned API.')
        ans = self._http_req(url, useragent='FastAudit_Agent') # as said in the site - better use a certain user-agent for this request
        self.ret()
        if ans.status_code == 200:
            print '{0}[x]{1} This password has been seen {0}{2}{1} times before'.format(B+RD, S, ans.text)
            if self.__save:
                logging.warning('This password has been seen {} times before.'.format(ans.text))
        else:
            print "{}[+]{} This password hasn't been seen before (that doesn't mean its safe)!".format(B+G, S)
            if self.__save:
                logging.warning("This password hasn't been seen before (that doesn't mean its safe though)!")


    def shodanSearch(self, domain):
        """utilize shodan to search for vulnerabilities"""
        try:
            api = shodan.Shodan(self.__key)
            print '\n{0}{2}[+]{1} Searching with {2}Shodan{1}...'.format(B, S, G)
    
            # Lookup the host
            host = api.host(self.resolve(domain))
            
            # Print general info
            print '\n{0}{2}[+]{1} IP: {2}{3}{1}'.format(B, S, G, host['ip_str'])
            print '{0}{2}[+]{1} Organization: {2}{3}{1}'.format(B, S, G, host.get('org', 'n/a'))
            print '{0}{2}[+]{1} Operating System: {2}{3}{1}'.format(B, S, G, host.get('os', 'Unknown'))
            
            # print open ports
            print '{}[{}x{}]{} Open ports found:'.format(B, RD, F, S)
            if host['data']:
                for i in host['data']:
                    print '  {0}╚══[Port]:{1} {2}{4}{1} ({3}{5}{1})'.format(B, S, G, C, i['port'], self.getService(i['port']))
            else:
                self.ret()
                print '{}[+]{} No open ports found!'.format(B+G, S)

            # search for possible vulnerabilities
            print '\n{}[+]{} Searching for {}vulnerabilities{}...'.format(B, S, RD, F)
            if host.get('vulns'):
                self.ret()
                print '{}[{}x{}]{} vulnerabilities found:'.format(B, RD, F, S)
                for vuln in host['vulns']:
                    print '  {0}╚══[vulnerability]:{1} {2}{3}{1}'.format(B, S, RD, vuln.replace('!',''))
                    exploits = api.exploits.search(vuln.replace('!',''))
                    if exploits['matches']:
                        for exp in exploits['matches']:
                            if exp.get('cve')[0] == vuln.replace('!',''):
                                print '{}Description:{}  {}'.format(B, S, exp.get('description'))
            else:
                self.ret()
                print '{}[+]{} No vulnerabilities found!'.format(B+G, S)
        except Exception, error:
            self.ret()
            print '{}[x] Unable to perform a shodan search!{}'.format(RD, S)
#_EOF