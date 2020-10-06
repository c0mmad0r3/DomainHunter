#!/usr/bin/python

import warnings
import sys
import getopt
import requests
import socket
from pypac import PACSession, get_pac
from requests.auth import HTTPProxyAuth
import logging
import urllib3
import time
import lxml
import queue
import argparse
import codecs
import socket
import ipwhois

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from lxml.html import fromstring
from urllib.parse import urlparse
from ipwhois import IPWhois
from importlib import reload

#logging.basicConfig(level=logging.DEBUG)

q = queue.Queue()

urllib3.disable_warnings()
parser = argparse.ArgumentParser(prog='esirp.py', description='EsiRP is a script designed to provide the HTTP response, Title, IP address, ASN Number and location for a domain and subdomains')
group = parser.add_mutually_exclusive_group()
group.add_argument("-i", "--ifile", dest="filename", help="Provide the filename containing the list of Domains")
group.add_argument("-d", "--domain", dest="domain", help="Provide a single Domain Name")
parser.add_argument("-w", "--wordlist", dest="wordlist", help="Provide the filename containing the list of Subdomain names")
parser.add_argument("-o", "--ofile", dest="output", help="Provide the filename to output results")
parser.add_argument("-p", "--proxy", dest="proxy", help="Send all traffic through a proxy")
parser.add_argument("-v", "--verbose", dest="verbose", help="Show logging", action="store_true")
args=parser.parse_args()

def subdomain(filename,wordlist):
    with codecs.open(args.filename, encoding='utf-8') as f:
        for line in f:
            url=line.rstrip()
            with open(args.wordlist) as w:
                for word in w:
                    sub1=word.rstrip()
                    sub=(sub1+"."+url)
                    try:
                        if 'http://' in sub:
                            r=requests.get(sub,timeout=10,verify=False)
                        elif 'https://' in sub:
                            r=requests.get(sub,timeout=10,verify=False)
                        else:
                            r=requests.get('http://'+sub,timeout=10,verify=False)
                        if r.history:
                            tree = fromstring(r.content)
                            title=(tree.findtext('.//title'))
                            redirdomain=urlparse(r.url)
                            newdom=str(redirdomain.netloc)
                            if title is not None:
                                if "comingsoon.markmonitor.com" in r.url:
                                    pass
                                elif (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                            
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+title+","+whoislkup)
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+title+","+whoislkup)
							
                            else:
                                if (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)

                        else:
                            tree = fromstring(r.content)
                            title=(tree.findtext('.//title'))
                            redirdomain=urlparse(r.url)
                            newdom=str(redirdomain.netloc)
                            if title is not  None:
                                statcode=str(r.status_code)
                                reasoncode=str(r.reason)
                                if ("40" not in statcode) and ("50" not in statcode):
                                    if (":80" in newdom) or (":443" in newdom):
                                        redirurl,redirport=newdom.split(':')
                                        whoislkup=(socket.gethostbyname(redirurl))
                                        with warnings.catch_warnings():
                                            warnings.filterwarnings("ignore", category=UserWarning)
                                            try:
                                                obj = IPWhois(whoislkup)
                                                results = obj.lookup_whois()
                                                ASNNumber=results['asn']
                                                ASNDesc=results['asn_description']
                                                if ASNDesc is not None:
                                                    print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                                else:
                                                    print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                                print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                                    else:
                                        whoislkup=(socket.gethostbyname(newdom))
                                        with warnings.catch_warnings():
                                            warnings.filterwarnings("ignore", category=UserWarning)
                                            try:
                                                obj = IPWhois(whoislkup)
                                                results = obj.lookup_whois()
                                                ASNNumber=results['asn']
                                                ASNDesc=results['asn_description']
                                                if ASNDesc is not None:
                                                    print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                                else:
                                                    print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                                print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                            else:
                                if (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                                
                    except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
                        pass
            w.close()

def domainfile(filename):
    f = codecs.open(filename, 'r', encoding='utf-8')
    for line in f:
        url=line.rstrip()
        try:
            if 'http://' in url:
                r=requests.get(url,timeout=10,verify=False)
            elif 'https://' in url:
                r=requests.get(url,timeout=10,verify=False)
            else:
                r=requests.get('http://'+url,timeout=10,verify=False)
            if r.history:
                tree = fromstring(r.content)
                title=(tree.findtext('.//title'))
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if title is not None:
                    if "comingsoon.markmonitor.com" in r.url:
                        pass
                    elif (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+title+","+whoislkup)
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+title+","+whoislkup)
                else:
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+" "+","+whoislkup)
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+" "+","+whoislkup)
            else:
                tree = fromstring(r.content)
                title=(tree.findtext('.//title'))
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if title is not None:
                    statcode=str(r.status_code)
                    reasoncode=str(r.reason)
                    if ("40" not in statcode) and ("50" not in statcode):
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")                                 
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup)			


                else:
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+" "+","+whoislkup)
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+" "+","+whoislkup)

        except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
            pass

def singledomain(domain):
    try:
        if 'http://' in domain:
            r=requests.get(domain,timeout=10,verify=False)
        elif 'https://' in domain:
            r=requests.get(domain,timeout=10,verify=False)
        else:
            r=requests.get('http://'+domain,timeout=10,verify=False)
        if r.history:
            tree = fromstring(r.content)
            title=tree.findtext('.//title')
            redirdomain=urlparse(r.url)
            newdom=str(redirdomain.netloc)
            if title is not None:
                if "comingsoon.markmonitor.com" in r.url:
                    pass
                elif (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                print(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                            
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+",was redirected to,"+r.url+","+title+","+whoislkup)
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                print(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+",was redirected to,"+r.url+","+title+","+whoislkup)						
            else:
                if "comingsoon.markmonitor.com" in r.url:
                    pass
                if (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")                   
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup)
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")                 
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup)
        else:
            tree = fromstring(r.content)
            title=(tree.findtext('.//title'))
            redirdomain=urlparse(r.url)
            newdom=str(redirdomain.netloc)
            if title is not None:
                statcode=str(r.status_code)
                reasoncode=str(r.reason)
                if ("40" not in statcode) and ("50" not in statcode):
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
            else:
                statcode=str(r.status_code)
                reasoncode=str(r.reason)
                if ("40" not in statcode) and ("50" not in statcode):
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(domain+","+statcode+" "+reasoncode+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    print(domain+","+statcode+" "+reasoncode+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(domain+","+statcode+" "+reasoncode+","+" "+","+whoislkup+"\n")
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(domain+","+statcode+" "+reasoncode+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    print(domain+","+statcode+" "+reasoncode+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(domain+","+statcode+" "+reasoncode+","+" "+","+whoislkup+"\n")
    except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
        pass
		
def subdomainoutputfile(filename,wordlist,o):
    with codecs.open(filename, encoding='utf-8') as f:
        for line in f:
            url=line.rstrip()
            with open(wordlist) as w:
                for word in w:
                    sub1=word.rstrip()
                    sub=(sub1+"."+url)
                    try:
                        if 'http://' in sub:
                            r=requests.get(sub,timeout=10,verify=False)
                        elif 'https://' in sub:
                            r=requests.get(sub,timeout=10,verify=False)
                        else:
                            r=requests.get('http://'+sub,timeout=10,verify=False)
                        if r.history:
                            tree = fromstring(r.content)
                            title=(tree.findtext('.//title'))
                            redirdomain=urlparse(r.url)
                            newdom=str(redirdomain.netloc)
                            if title is not None:
                                if "comingsoon.markmonitor.com" in r.url:
                                    pass
                                elif (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+"\n")
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+"\n")		
                            else:
                                if (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                        else:
                            tree = fromstring(r.content)
                            title=(tree.findtext('.//title'))
                            redirdomain=urlparse(r.url)
                            newdom=str(redirdomain.netloc)
                            if title is not None:
                                statcode=str(r.status_code)
                                reasoncode=str(r.reason)
                                redirdomain=urlparse(r.url)
                                newdom=str(redirdomain.netloc)
                                if ("40" not in statcode) and ("50" not in statcode):
                                    if (":80" in newdom) or (":443" in newdom):
                                        redirurl,redirport=newdom.split(':')
                                        whoislkup=(socket.gethostbyname(redirurl))
                                        with warnings.catch_warnings():
                                            warnings.filterwarnings("ignore", category=UserWarning)
                                            try:
                                                obj = IPWhois(whoislkup)
                                                results = obj.lookup_whois()
                                                ASNNumber=results['asn']
                                                ASNDesc=results['asn_description']
                                                if ASNDesc is not None:
                                                    o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                                else:
                                                    o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                                o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
                                    else:
                                        whoislkup=(socket.gethostbyname(newdom))
                                        with warnings.catch_warnings():
                                            warnings.filterwarnings("ignore", category=UserWarning)
                                            try:
                                                obj = IPWhois(whoislkup)
                                                results = obj.lookup_whois()
                                                ASNNumber=results['asn']
                                                ASNDesc=results['asn_description']
                                                if ASNDesc is not None:
                                                    o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                                else:
                                                    o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                                o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")				
                            else:
                                if (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                    except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
                        pass
            w.close()

def domainoutputfile(filename,o):
    f = codecs.open(filename, 'r', encoding='utf-8')
    for line in f:
        url=line.rstrip()
        try:
            if 'http://' in url:
                r=requests.get(url,timeout=10,verify=False)
            elif 'https://' in url:
                r=requests.get(url,timeout=10,verify=False)
            else:
                r=requests.get('http://'+url,timeout=10,verify=False)
            if r.history:
                tree = fromstring(r.content)
                title=(tree.findtext('.//title'))
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if title is not None:
                    if "comingsoon.markmonitor.com" in r.url:
                        pass
                    elif (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+"\n")
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+"\n")								
                else:
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")

            else:
                tree = fromstring(r.content)
                title=(tree.findtext('.//title'))
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if title is not None:
                    statcode=str(r.status_code)
                    reasoncode=str(r.reason)
                    if ("40" not in statcode) and ("50" not in statcode):
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                    else:
                                        o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                    else:
                                        o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
                else:
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")

        except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
            pass

def singledomainoutputfile(domain,o):
    try:
        if 'http://' in domain:
            r=requests.get(domain,timeout=10,verify=False)
        elif 'https://' in domain:
            r=requests.get(domain,timeout=10,verify=False)
        else:
            r=requests.get('http://'+domain,timeout=10,verify=False)
        if r.history:
            tree = fromstring(r.content)
            title=tree.findtext('.//title')
            redirdomain=urlparse(r.url)
            newdom=str(redirdomain.netloc)
            if title is not None:
                if "comingsoon.markmonitor.com" in r.url:
                    pass
                elif (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                            
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup)
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup)							
            else:
                if (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")                    
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup)
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")                    
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup)
        else:
            tree = fromstring(r.content)
            title=(tree.findtext('.//title'))
            redirdomain=urlparse(r.url)
            newdom=str(redirdomain.netloc)
            if title is not None:
                statcode=str(r.status_code)
                reasoncode=str(r.reason)
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if ("40" not in statcode) and ("50" not in statcode):
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                            else:
                                o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")				
            else:
                if (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
    except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
            pass

        
def singlesuboutput (domain,wordlist):
    with open(wordlist) as w:
        for word in w:
            sub1=word.rstrip()
            sub=(sub1+"."+domain)
            try:
                if 'http://' in sub:
                    r=requests.get(sub,timeout=10,verify=False)
                elif 'https://' in sub:
                    r=requests.get(sub,timeout=10,verify=False)
                else:
                    r=requests.get('http://'+sub,timeout=10,verify=False)
                if r.history:
                    tree = fromstring(r.content)
                    title=(tree.findtext('.//title'))
                    redirdomain=urlparse(r.url)
                    newdom=str(redirdomain.netloc)
                    if title is not None:
                        if "comingsoon.markmonitor.com" in r.url:
                            pass
                        elif (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+title+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+title+","+whoislkup)
                    else:
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                else:
                    tree = fromstring(r.content)
                    title=(tree.findtext('.//title'))
                    redirdomain=urlparse(r.url)
                    newdom=str(redirdomain.netloc)
                    if title is not None:
                        statcode=str(r.status_code)
                        reasoncode=str(r.reason)
                        if ("40" not in statcode) and ("50" not in statcode):
                            if (":80" in newdom) or (":443" in newdom):
                                redirurl,redirport=newdom.split(':')
                                whoislkup=(socket.gethostbyname(redirurl))
                                with warnings.catch_warnings():
                                    warnings.filterwarnings("ignore", category=UserWarning)
                                    try:
                                        obj = IPWhois(whoislkup)
                                        results = obj.lookup_whois()
                                        ASNNumber=results['asn']
                                        ASNDesc=results['asn_description']
                                        if ASNDesc is not None:
                                            print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                        else:
                                            print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                    except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                        print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                            else:
                                whoislkup=(socket.gethostbyname(newdom))
                                with warnings.catch_warnings():
                                    warnings.filterwarnings("ignore", category=UserWarning)
                                    try:
                                        obj = IPWhois(whoislkup)
                                        results = obj.lookup_whois()
                                        ASNNumber=results['asn']
                                        ASNDesc=results['asn_description']
                                        if ASNDesc is not None:
                                            print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                        else:
                                            print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                    except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                        print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                    else:
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
            except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
                pass

def singlesuboutputfile (domain,wordlist,o):
    with open(wordlist) as w:
        for word in w:
            sub1=word.rstrip()
            sub=(sub1+"."+domain)
            try:
                if 'http://' in sub:
                    r=requests.get(sub,timeout=10,verify=False)
                elif 'https://' in sub:
                    r=requests.get(sub,timeout=10,verify=False)
                else:
                    r=requests.get('http://'+sub,timeout=10,verify=False)
                if r.history:
                    tree = fromstring(r.content)
                    title=(tree.findtext('.//title'))
                    redirdomain=urlparse(r.url)
                    newdom=str(redirdomain.netloc)
                    if title is not None:
                        if "comingsoon.markmonitor.com" in r.url:
                            pass
                        elif (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup)							
                    else:
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                else:
                    tree = fromstring(r.content)
                    title=(tree.findtext('.//title'))
                    redirdomain=urlparse(r.url)
                    newdom=str(redirdomain.netloc)
                    if title is not None:
                        statcode=str(r.status_code)
                        reasoncode=str(r.reason)
                        if ("40" not in statcode) and ("50" not in statcode):
                            if (":80" in newdom) or (":443" in newdom):
                                redirurl,redirport=newdom.split(':')
                                whoislkup=(socket.gethostbyname(redirurl))
                                with warnings.catch_warnings():
                                    warnings.filterwarnings("ignore", category=UserWarning)
                                    try:
                                        obj = IPWhois(whoislkup)
                                        results = obj.lookup_whois()
                                        ASNNumber=results['asn']
                                        ASNDesc=results['asn_description']
                                        if ASNDesc is not None:
                                            o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                        else:
                                            o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                    except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                        o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                            else:
                                whoislkup=(socket.gethostbyname(newdom))
                                with warnings.catch_warnings():
                                    warnings.filterwarnings("ignore", category=UserWarning)
                                    try:
                                        obj = IPWhois(whoislkup)
                                        results = obj.lookup_whois()
                                        ASNNumber=results['asn']
                                        ASNDesc=results['asn_description']
                                        if ASNDesc is not None:
                                            o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                        else:
                                            o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                    except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                        o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                    else:
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
            except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
                pass
				
def subdomainp(filename,wordlist,proxy):
    pac = get_pac(url=str(proxy))
    session=PACSession(pac)
    with codecs.open(args.filename, encoding='utf-8') as f:
        for line in f:
            url=line.rstrip()
            with open(args.wordlist) as w:
                for word in w:
                    sub1=word.rstrip()
                    sub=(sub1+"."+url)
                    try:
                        if 'http://' in sub:
                            r=session.get(sub,timeout=10,verify=False)
                        elif 'https://' in sub:
                            r=session.get(sub,timeout=10,verify=False)
                        else:
                            r=session.get('http://'+sub,timeout=10,verify=False)
                        if r.history:
                            tree = fromstring(r.content)
                            title=(tree.findtext('.//title'))
                            redirdomain=urlparse(r.url)
                            newdom=str(redirdomain.netloc)
                            if title is not None:
                                if "comingsoon.markmonitor.com" in r.url:
                                    pass
                                elif (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+title+","+whoislkup)
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+title+","+whoislkup)
                            else:
                                if (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                        else:
                            tree = fromstring(r.content)
                            title=(tree.findtext('.//title'))
                            redirdomain=urlparse(r.url)
                            newdom=str(redirdomain.netloc)
                            if title is not None:
                                statcode=str(r.status_code)
                                reasoncode=str(r.reason)
                                if ("40" not in statcode) and ("50" not in statcode):
                                    if (":80" in newdom) or (":443" in newdom):
                                        redirurl,redirport=newdom.split(':')
                                        whoislkup=(socket.gethostbyname(redirurl))
                                        with warnings.catch_warnings():
                                            warnings.filterwarnings("ignore", category=UserWarning)
                                            try:
                                                obj = IPWhois(whoislkup)
                                                results = obj.lookup_whois()
                                                ASNNumber=results['asn']
                                                ASNDesc=results['asn_description']
                                                if ASNDesc is not None:
                                                    print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                                else:
                                                    print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                                print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                                    else:
                                        whoislkup=(socket.gethostbyname(newdom))
                                        with warnings.catch_warnings():
                                            warnings.filterwarnings("ignore", category=UserWarning)
                                            try:
                                                obj = IPWhois(whoislkup)
                                                results = obj.lookup_whois()
                                                ASNNumber=results['asn']
                                                ASNDesc=results['asn_description']
                                                if ASNDesc is not None:
                                                    print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                                else:
                                                    print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                                print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                            else:
                                if (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                            else:
                                                print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                    except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
                        pass
            w.close()

def domainfilep(filename,proxy):
    pac = get_pac(url=str(proxy))
    session=PACSession(pac)
    f = codecs.open(filename, 'r', encoding='utf-8')
    for line in f:
        url=line.rstrip()
        try:
            if 'http://' in url:
                r=session.get(url,timeout=10,verify=False)
            elif 'https://' in url:
                r=session.get(url,timeout=10,verify=False)
            else:
                r=session.get('http://'+url,timeout=10,verify=False)
            if r.history:
                tree = fromstring(r.content)
                title=(tree.findtext('.//title'))
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if title is not None:
                    if "comingsoon.markmonitor.com" in r.url:
                        pass
                    elif (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+title+","+whoislkup)
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+title+","+whoislkup)
                else:
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+title+","+whoislkup)
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+title+","+whoislkup)
            else:
                tree = fromstring(r.content)
                title=(tree.findtext('.//title'))
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if title is not None:
                    statcode=str(r.status_code)
                    reasoncode=str(r.reason)
                    if ("40" not in statcode) and ("50" not in statcode):
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(url+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                else:
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+" "+","+whoislkup)
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                else:
                                    print(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(url+",was redirected to,"+r.url+","+" "+","+whoislkup)
        except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
            pass

def singledomainp(domain,proxy):
    pac = get_pac(url=str(proxy))
    session=PACSession(pac)
    try:
        if 'http://' in domain:
            r=session.get(domain,timeout=10,verify=False)
        elif 'https://' in domain:
            r=session.get(domain,timeout=10,verify=False)
        else:
            r=session.get('http://'+domain,timeout=10,verify=False)
        if r.history:
            tree = fromstring(r.content)
            title=tree.findtext('.//title')
            redirdomain=urlparse(r.url)
            newdom=str(redirdomain.netloc)
            if title is not None:
                if "comingsoon.markmonitor.com" in r.url:
                    pass
                elif (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                print(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+",was redirected to,"+r.url+","+title+","+whoislkup)
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                print(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+",was redirected to,"+r.url+","+title+","+whoislkup)			
            else:
                if (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")                 
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup)
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")                 
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup)
        else:
            tree = fromstring(r.content)
            title=(tree.findtext('.//title'))
            redirdomain=urlparse(r.url)
            newdom=str(redirdomain.netloc)
            if title is not None:
                statcode=str(r.status_code)
                reasoncode=str(r.reason)
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if ("40" not in statcode) and ("50" not in statcode):
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                            else:
                                print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")	
            else:
                if (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                            else:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                            else:
                                print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            print(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
    except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
            pass

def subdomainoutputfilep(filename,wordlist,o,proxy):
    pac = get_pac(url=str(proxy))
    session=PACSession(pac)
    with codecs.open(filename, encoding='utf-8') as f:
        for line in f:
            url=line.rstrip()
            with open(wordlist) as w:
                for word in w:
                    sub1=word.rstrip()
                    sub=(sub1+"."+url)
                    try:
                        if 'http://' in sub:
                            r=session.get(sub,timeout=10,verify=False)
                        elif 'https://' in sub:
                            r=session.get(sub,timeout=10,verify=False)
                        else:
                            r=session.get('http://'+sub,timeout=10,verify=False)
                        if r.history:
                            tree = fromstring(r.content)
                            title=(tree.findtext('.//title'))
                            redirdomain=urlparse(r.url)
                            newdom=str(redirdomain.netloc)
                            if title is not None:
                                if "comingsoon.markmonitor.com" in r.url:
                                    pass
                                elif (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+"\n")
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+"\n")		
                            else:
                                if (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                        else:
                            tree = fromstring(r.content)
                            title=(tree.findtext('.//title'))
                            redirdomain=urlparse(r.url)
                            newdom=str(redirdomain.netloc)
                            if title is not None:
                                statcode=str(r.status_code)
                                reasoncode=str(r.reason)
                                redirdomain=urlparse(r.url)
                                newdom=str(redirdomain.netloc)
                                if ("40" not in statcode) and ("50" not in statcode):
                                    if (":80" in newdom) or (":443" in newdom):
                                        redirurl,redirport=newdom.split(':')
                                        whoislkup=(socket.gethostbyname(redirurl))
                                        with warnings.catch_warnings():
                                            warnings.filterwarnings("ignore", category=UserWarning)
                                            try:
                                                obj = IPWhois(whoislkup)
                                                results = obj.lookup_whois()
                                                ASNNumber=results['asn']
                                                ASNDesc=results['asn_description']
                                                if ASNDesc is not None:
                                                    o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                                else:
                                                    o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                                o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
                                    else:
                                        whoislkup=(socket.gethostbyname(newdom))
                                        with warnings.catch_warnings():
                                            warnings.filterwarnings("ignore", category=UserWarning)
                                            try:
                                                obj = IPWhois(whoislkup)
                                                results = obj.lookup_whois()
                                                ASNNumber=results['asn']
                                                ASNDesc=results['asn_description']
                                                if ASNDesc is not None:
                                                    o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                                else:
                                                    o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                                o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")				
                            else:
                                if (":80" in newdom) or (":443" in newdom):
                                    redirurl,redirport=newdom.split(':')
                                    whoislkup=(socket.gethostbyname(redirurl))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                                else:
                                    whoislkup=(socket.gethostbyname(newdom))
                                    with warnings.catch_warnings():
                                        warnings.filterwarnings("ignore", category=UserWarning)
                                        try:
                                            obj = IPWhois(whoislkup)
                                            results = obj.lookup_whois()
                                            ASNNumber=results['asn']
                                            ASNDesc=results['asn_description']
                                            if ASNDesc is not None:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                            else:
                                                o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                            o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                    except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
                        pass
            w.close()
			
def domainoutputfilep(filename,o,proxy):
    pac = get_pac(url=str(proxy))
    session=PACSession(pac)
    f = codecs.open(filename, 'r', encoding='utf-8')
    for line in f:
        url=line.rstrip()
        try:
            if 'http://' in url:
                r=session.get(url,timeout=10,verify=False)
            elif 'https://' in url:
                r=session.get(url,timeout=10,verify=False)
            else:
                r=session.get('http://'+url,timeout=10,verify=False)
            if r.history:
                tree = fromstring(r.content)
                title=(tree.findtext('.//title'))
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if title is not None:
                    if "comingsoon.markmonitor.com" in r.url:
                        pass
                    elif (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+"\n")
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+title+","+whoislkup+"\n")								
                else:
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
            else:
                tree = fromstring(r.content)
                title=(tree.findtext('.//title'))
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if title is not None:
                    statcode=str(r.status_code)
                    reasoncode=str(r.reason)
                    if ("40" not in statcode) and ("50" not in statcode):
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                    else:
                                        o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                    else:
                                        o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(url+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
                else:
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                    else:
                        whoislkup=(socket.gethostbyname(newdom))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(url+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")

        except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
            pass
			
def singledomainoutputfilep(domain,o,proxy):
    pac = get_pac(url=str(proxy))
    session=PACSession(pac)
    try:
        if 'http://' in domain:
            r=session.get(domain,timeout=10,verify=False)
        elif 'https://' in domain:
            r=session.get(domain,timeout=10,verify=False)
        else:
            r=session.get('http://'+domain,timeout=10,verify=False)
        if r.history:
            tree = fromstring(r.content)
            title=tree.findtext('.//title')
            redirdomain=urlparse(r.url)
            newdom=str(redirdomain.netloc)
            if title is not None:
                if "comingsoon.markmonitor.com" in r.url:
                    pass
                elif (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                            
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup)
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+title+","+whoislkup)							
            else:
                if (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")                    
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup)
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")                    
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup)
        else:
            tree = fromstring(r.content)
            title=(tree.findtext('.//title'))
            redirdomain=urlparse(r.url)
            newdom=str(redirdomain.netloc)
            if title is not None:
                statcode=str(r.status_code)
                reasoncode=str(r.reason)
                redirdomain=urlparse(r.url)
                newdom=str(redirdomain.netloc)
                if ("40" not in statcode) and ("50" not in statcode):
                    if (":80" in newdom) or (":443" in newdom):
                        redirurl,redirport=newdom.split(':')
                        whoislkup=(socket.gethostbyname(redirurl))
                        with warnings.catch_warnings():
                            warnings.filterwarnings("ignore", category=UserWarning)
                            try:
                                obj = IPWhois(whoislkup)
                                results = obj.lookup_whois()
                                ASNNumber=results['asn']
                                ASNDesc=results['asn_description']
                                if ASNDesc is not None:
                                    o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                                else:
                                    o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                            except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                            else:
                                o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None\n")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+","+statcode+" "+reasoncode+","+title+","+whoislkup+"\n")				
            else:
                if (":80" in newdom) or (":443" in newdom):
                    redirurl,redirport=newdom.split(':')
                    whoislkup=(socket.gethostbyname(redirurl))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
                else:
                    whoislkup=(socket.gethostbyname(newdom))
                    with warnings.catch_warnings():
                        warnings.filterwarnings("ignore", category=UserWarning)
                        try:
                            obj = IPWhois(whoislkup)
                            results = obj.lookup_whois()
                            ASNNumber=results['asn']
                            ASNDesc=results['asn_description']
                            if ASNDesc is not None:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc+"\n")
                            else:
                                o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None\n")
                        except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                            o.write(domain+",was redirected to,"+r.url+","+" "+","+whoislkup+"\n")
    except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
            pass

def singlesuboutputp (domain,wordlist,proxy):
    pac = get_pac(url=str(proxy))
    session=PACSession(pac)
    with open(wordlist) as w:
        for word in w:
            sub1=word.rstrip()
            sub=(sub1+"."+domain)
            try:
                if 'http://' in sub:
                    r=session.get(sub,timeout=10,verify=False)
                elif 'https://' in sub:
                    r=session.get(sub,timeout=10,verify=False)
                else:
                    r=session.get('http://'+sub,timeout=10,verify=False)
                if r.history:
                    tree = fromstring(r.content)
                    title=(tree.findtext('.//title'))
                    redirdomain=urlparse(r.url)
                    newdom=str(redirdomain.netloc)
                    if title is not None:
                        if "comingsoon.markmonitor.com" in r.url:
                            pass
                        elif (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+title+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+title+","+whoislkup)				
                    else:
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                else:
                    tree = fromstring(r.content)
                    title=(tree.findtext('.//title'))
                    redirdomain=urlparse(r.url)
                    newdom=str(redirdomain.netloc)
                    if title is not None:
                        statcode=str(r.status_code)
                        reasoncode=str(r.reason)
                        if ("40" not in statcode) and ("50" not in statcode):
                            if (":80" in newdom) or (":443" in newdom):
                                redirurl,redirport=newdom.split(':')
                                whoislkup=(socket.gethostbyname(redirurl))
                                with warnings.catch_warnings():
                                    warnings.filterwarnings("ignore", category=UserWarning)
                                    try:
                                        obj = IPWhois(whoislkup)
                                        results = obj.lookup_whois()
                                        ASNNumber=results['asn']
                                        ASNDesc=results['asn_description']
                                        if ASNDesc is not None:
                                            print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                        else:
                                            print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                    except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                        print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                            else:
                                whoislkup=(socket.gethostbyname(newdom))
                                with warnings.catch_warnings():
                                    warnings.filterwarnings("ignore", category=UserWarning)
                                    try:
                                        obj = IPWhois(whoislkup)
                                        results = obj.lookup_whois()
                                        ASNNumber=results['asn']
                                        ASNDesc=results['asn_description']
                                        if ASNDesc is not None:
                                            print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                        else:
                                            print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                    except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                        print(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                    else:
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    print(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
            except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
                pass

def singlesuboutputfilep (domain,wordlist,o,proxy):
    pac = get_pac(url=str(proxy))
    session=PACSession(pac)
    with open(wordlist) as w:
        for word in w:
            sub1=word.rstrip()
            sub=(sub1+"."+domain)
            try:
                if 'http://' in sub:
                    r=session.get(sub,timeout=10,verify=False)
                elif 'https://' in sub:
                    r=session.get(sub,timeout=10,verify=False)
                else:
                    r=session.get('http://'+sub,timeout=10,verify=False)
                if r.history:
                    tree = fromstring(r.content)
                    title=(tree.findtext('.//title'))
                    redirdomain=urlparse(r.url)
                    newdom=str(redirdomain.netloc)
                    if title is not None:
                        if "comingsoon.markmonitor.com" in r.url:
                            pass
                        elif (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+title+","+whoislkup)							
                    else:
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                else:
                    tree = fromstring(r.content)
                    title=(tree.findtext('.//title'))
                    redirdomain=urlparse(r.url)
                    newdom=str(redirdomain.netloc)
                    if title is not None:
                        statcode=str(r.status_code)
                        reasoncode=str(r.reason)
                        if ("40" not in statcode) and ("50" not in statcode):
                            if (":80" in newdom) or (":443" in newdom):
                                redirurl,redirport=newdom.split(':')
                                whoislkup=(socket.gethostbyname(redirurl))
                                with warnings.catch_warnings():
                                    warnings.filterwarnings("ignore", category=UserWarning)
                                    try:
                                        obj = IPWhois(whoislkup)
                                        results = obj.lookup_whois()
                                        ASNNumber=results['asn']
                                        ASNDesc=results['asn_description']
                                        if ASNDesc is not None:
                                            o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                        else:
                                            o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                    except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                        o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                            else:
                                whoislkup=(socket.gethostbyname(newdom))
                                with warnings.catch_warnings():
                                    warnings.filterwarnings("ignore", category=UserWarning)
                                    try:
                                        obj = IPWhois(whoislkup)
                                        results = obj.lookup_whois()
                                        ASNNumber=results['asn']
                                        ASNDesc=results['asn_description']
                                        if ASNDesc is not None:
                                            o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                        else:
                                            o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup+","+ASNNumber+",None")
                                    except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                        o.write(sub+","+statcode+" "+reasoncode+","+title+","+whoislkup)
                    else:
                        if (":80" in newdom) or (":443" in newdom):
                            redirurl,redirport=newdom.split(':')
                            whoislkup=(socket.gethostbyname(redirurl))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
                        else:
                            whoislkup=(socket.gethostbyname(newdom))
                            with warnings.catch_warnings():
                                warnings.filterwarnings("ignore", category=UserWarning)
                                try:
                                    obj = IPWhois(whoislkup)
                                    results = obj.lookup_whois()
                                    ASNNumber=results['asn']
                                    ASNDesc=results['asn_description']
                                    if ASNDesc is not None:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+","+ASNDesc)
                                    else:
                                        o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup+","+ASNNumber+",None")
                                except (ipwhois.exceptions.WhoisLookupError,ipwhois.exceptions.IPDefinedError) as error:
                                    o.write(sub+",was redirected to,"+r.url+","+" "+","+whoislkup)
            except (lxml.etree.ParserError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as error :
                pass
                
def main(argv):
    try:
        if (args.filename) and (args.wordlist) and (args.output) and (args.proxy) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            o=codecs.open(args.output,'w')
            subdomainoutputfilep(args.filename,args.wordlist,o,args.proxy)
        elif (args.filename) and (args.wordlist) and (args.output) and (args.proxy):
            o=codecs.open(args.output,'w')
            subdomainoutputfilep(args.filename,args.wordlist,o,args.proxy)
        elif (args.domain) and (args.wordlist) and (args.output) and (args.proxy) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            o=codecs.open(args.output,'w')
            singlesuboutputfilep(args.domain,args.wordlist,o,args.proxy)
        elif (args.domain) and (args.wordlist) and (args.output) and (args.proxy):
            o=codecs.open(args.output,'w')
            singlesuboutputfilep(args.domain,args.wordlist,o,args.proxy)
        elif (args.filename) and (args.wordlist) and (args.output) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            o=codecs.open(args.output,'w')
            subdomainoutputfile(args.filename,args.wordlist,o)
        elif (args.filename) and (args.wordlist) and (args.output):
            o=codecs.open(args.output,'w')
            subdomainoutputfile(args.filename,args.wordlist,o)
        elif (args.domain) and (args.wordlist) and (args.output) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            o=codecs.open(args.output,'w')
            singlesuboutputfile(args.domain,args.wordlist,o)
        elif (args.domain) and (args.wordlist) and (args.output):
            o=codecs.open(args.output,'w')
            singlesuboutputfile(args.domain,args.wordlist,o)
        elif (args.filename) and (args.wordlist) and (args.proxy) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            subdomainp(args.filename,args.wordlist,args.proxy)
        elif (args.filename) and (args.wordlist) and (args.proxy):
            subdomainp(args.filename,args.wordlist,args.proxy)
        elif (args.domain) and (args.output) and (args.proxy) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            o=codecs.open(args.output,'w')
            singledomainoutputfilep(args.domain,o,args.proxy)
        elif (args.domain) and (args.output) and (args.proxy):
            o=codecs.open(args.output,'w')
            singledomainoutputfilep(args.domain,o,args.proxy)
        elif (args.domain) and (args.wordlist) and (args.proxy) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            singlesuboutputp(args.domain,args.wordlist,args.proxy)
        elif (args.domain) and (args.wordlist) and (args.proxy):
            singlesuboutputp(args.domain,args.wordlist,args.proxy)
        elif (args.filename) and (args.wordlist) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            subdomain(args.filename,args.wordlist)
        elif (args.filename) and (args.wordlist):
            subdomain(args.filename,args.wordlist)
        elif (args.domain) and (args.wordlist) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            singlesuboutput(args.domain,args.wordlist)
        elif (args.domain) and (args.wordlist):
            singlesuboutput(args.domain,args.wordlist)
        elif (args.filename) and (args.output) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            o=codecs.open(args.output,'w')
            domainoutputfile(args.filename,o)
        elif (args.filename) and (args.output):
            o=codecs.open(args.output,'w')
            domainoutputfile(args.filename,o)
        elif (args.domain) and (args.output) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            o=codecs.open(args.output,'w')
            singledomainoutputfile(args.domain,o)
        elif (args.domain) and (args.output):
            o=codecs.open(args.output,'w')
            singledomainoutputfile(args.domain,o)
        elif (args.filename) and (args.proxy) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            domainfilep(args.filename,args.proxy)
        elif (args.filename) and (args.proxy):
            domainfilep(args.filename,args.proxy)
        elif (args.domain) and (args.proxy) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            singledomainp(args.domain,args.proxy)
        elif (args.domain) and (args.proxy):
            singledomainp(args.domain,args.proxy)
        elif (args.filename) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            domainfile(args.filename)
        elif (args.filename):
            domainfile(args.filename)
        elif (args.domain) and (args.verbose):
            logging.basicConfig(level=logging.DEBUG)
            singledomain(args.domain)
        elif (args.domain):
            singledomain(args.domain)
        else:
            print(args)
    except KeyboardInterrupt:
        print('Exiting...')
    except IOError:
        print('Failed to open input file/domain ' + args.filename + ' for reading')
        print('Exiting...!')
        sys.exit(2)     
        
if __name__ == "__main__":
    try:
        argv = sys.argv
    except IndexError:
        sys.exit(2)
    main(sys.argv[1:])
