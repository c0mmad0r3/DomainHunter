# EsiRP
EsiRP is a script designed to provide the HTTP response, Title, IP address, ASN Number and location for a domain and subdomains

# Install

pip install -r requirements.txt

# Usage
usage: esirp.py [-h] [-i FILENAME | -d DOMAIN] [-w WORDLIST] [-o OUTPUT] [-p PROXY] [-v]

<p>-h, --help                                                show this help message and exit</p>
<p>-i <filename>, --ifile <filename>                         Provide the filename containing the list of Domains</p>
<p>-d <domain>, --domain <domain>                            Provide a single Domain Name</p>
<p>-w <wordlist filename>, --wordlist <wordlist filename>    Provide the filename containing the list of Subdomain names</p>
<p>-o <output filename>, --ofile <output filename>           Provide the filename to output results</p>
<p>-p <ip address>, --proxy <ip address>                     Send all traffic through a proxy</p>
<p>-v, --verbose                                             Show logging</p>


# Example Output:

#python3 esirp.py -d testfire.net -w subdomains-100.txt
<p>ftp.testfire.net,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US</p>
<p>localhost.testfire.net,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US</p>
<p>demo.testfire.net,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US</p>
<p>www[.]testfire.net,200 OK,Altoro Mutual,65.61.137.117,33070,RMH-14 - Rackspace Hosting, US</p>
#
