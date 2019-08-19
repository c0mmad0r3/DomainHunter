# EsiRP
EsiRP is a script designed to provide the HTTP response, Title, IP address, ASN Number and location for a domain and subdomains

# Usage
usage: esirp.py [-h] [-i FILENAME | -d DOMAIN] [-w WORDLIST] [-o OUTPUT] [-p PROXY] [-v]


-h, --help                                                show this help message and exit

-i <filename>, --ifile <filename>                         Provide the filename containing the list of Domains

-d <domain>, --domain <domain>                            Provide a single Domain Name

-w <wordlist filename>, --wordlist <wordlist filename>    Provide the filename containing the list of Subdomain names

-o <output filename>, --ofile <output filename>           Provide the filename to output results

-p <ip address>, --proxy <ip address>                     Send all traffic through a proxy

-v, --verbose                                             Show logging


# Example Output:

#python3 esirp.py -d testfire.net -w subdomains-100.txt

<b>ftp.testfire.net</b>,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US

<b>localhost.testfire.net</b>,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US

<b>demo.testfire.net</b>,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US

<b>www.testfire.net</b> OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US

#
