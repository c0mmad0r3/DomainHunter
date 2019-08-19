#EsiRP

EsiRP is a script designed to provide the HTTP response, Title, IP address, ASN Number and location for a domain and subdomains

usage: esirp.py [-h] [-i FILENAME | -d DOMAIN] [-w WORDLIST] [-o OUTPUT] [-p PROXY] [-v]

-h, --help                          show this help message and exit

-i FILENAME, --ifile FILENAME       Provide the filename containing the list of Domains

-d DOMAIN, --domain DOMAIN          Provide a single Domain Name

-w WORDLIST, --wordlist WORDLIST    Provide the filename containing the list of Subdomain names

-o OUTPUT, --ofile OUTPUT           Provide the filename to output results

-p PROXY, --proxy PROXY             Send all traffic through a proxy

-v, --verbose                       Show logging


Example Output:

# python3 esirp.py -d testfire.net -w subdomains-100.txt

ftp.testfire.net,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US

localhost.testfire.net,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US

demo.testfire.net,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US

www.testfire.net,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US


