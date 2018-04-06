# Description  

(c) Arnim Eijkhoudt \<arnime _squiggly_ kpn-cert.nl\>, 2017, KPN-CERT, GPLv2 license
  
Netchecker lets you offline-check a list of IP addresses and CIDRs against known AS numbers/names. Works with both IPv4 and IPv6! This tool is useful for checking of e.g. leaked/dumped IPs/CIDRs against ASNs to see if there are matches, without having to use internet sources and thereby risking the possibility of announcing your interest in the checked addresses/ranges.
  
Netchecker automatically groks the entirety of any text file for anything resembling an IPv4 or IPv6 address or CIDR-notation, and will determine if any of those belong to one of the AS numbers/names you specified. The output shows the IP/CIDR found and which exact subnet it belongs to - useful for helping to determine the ownership for delegated prefixes.

# Requirements  
  
1) Python 2.7.x / 3.x (should work with both...)
2) [required] netaddr module (installable through PyPi etc.): https://pypi.python.org/pypi/netaddr
3) [required] For Python 2.7: ipaddress module: https://pypi.python.org/pypi/py2-ipaddress
4) [optional] MaxMind's GeoLite ASN databases: http://dev.maxmind.com/geoip/legacy/geolite/
  
# Installation  
  
1) git clone https://github.com/uforia/netchecker.git
2) pip install netaddr, apt-get install python-netaddr, emerge dev-python/netaddr or whatever else you use for package management
3) if using Python 2.x, install py-ipaddress (pip install ipaddress, etc.)

# Usage  
  
1) For your first run, create the GeoCache db first by running netchecker with the -u option.
2) Run netchecker over any text-based file containing IPv4 and/or IPv6 addresses/CIDRs, and specify the ASNs to look for:
   ./netchecker.py -f \<ip-file\> \<ASname\> \<ASname\> \<ASnumber...\> ... etc.

Usage notes:
- netchecker will automatically carve out anything that looks like an IPv4/IPv6/CIDR address; you do NOT need to have them neatly listed!
- certain flags can be combined, e.g. to -u(pdate) and -f(ind) at the same time

# Caveats, miscellaneous, TODO, etc.  
  
- The more AS names/numbers you check, the longer it takes to build the list of netblocks to verify against! This is particularly noticeable when you're using the -a/-all option.
- This product uses GeoLite data created by MaxMind, available from http://www.maxmind.com
