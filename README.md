# Description  

(c) Arnim Eijkhoudt \<arnime _squiggly_ kpn-cert.nl\>, 2017-2019, KPN-CERT, GPLv2 license
  
Netchecker lets you run an offline-check of list of IPv4- and IPv6-addresses and CIDRs against all known AS numbers/names. This tool is particularly useful for checking leaked/dumped IPs/CIDRs against your ASNs to see if there are any matches, without having to use online-only internet resources (this mitigates OPSEC leaks: you do not have to announce your interest in the checked addresses/ranges).
  
Netchecker automatically parses the entirety of any text file (unstructured or not) for anything resembling an IPv4 address, IPv6 address or a CIDR-netblock, and will determine if any of those belong to one of the AS numbers/names you specified as keyword searches. The output will show:

1) which IPs/CIDRs were found in which ASNs
2) to which exact subnet the IPs/CIDRs belong (useful for helping to determine the ownership for delegated prefixes)
3) how many IPs/CIDRs were found in the source file
4) how many of the IPs/CIDRs found in the source file were discovered in the searched ASNs
5) how many of the IPs/CIDRs found in the source file were NOT discovered in the searched ASNs
6) which of the found IPs/CIDRs from the source file were NOT discovered in the searched ASNs

# Requirements  
  
1) Python 3.x (sorry, Python 2.x is no longer supported due to the need for the ipaddress module/features)
2) [required] MaxMind's GeoLite ASN databases: https://geolite.maxmind.com/download/geoip/database/ (auto-download possible)
  
# Installation  
  
1) git clone https://github.com/KPN-CISO/netchecker/

# Usage  
  
1) For your first run, create the GeoCache db first by running netchecker with the -u option.
2) Run netchecker over any text-based file containing IPv4 and/or IPv6 addresses/CIDRs, and specify the ASNs to look for or use the '-a' option to list all IP <-> ASN relationships:

   ./netchecker.py -f \<ip-file\> \<ASname\> \<ASname\> \<ASnumber...\> ... etc.

Usage notes:
- netchecker will automatically carve out anything that looks like an IPv4/IPv6/CIDR address; you do NOT need to have them neatly listed!
- certain flags can be combined, e.g. to -u(pdate) and -f(ind) at the same time

# Caveats, miscellaneous, TODO, etc.  
  
- This product uses GeoLite data created by MaxMind, available from http://www.maxmind.com
