# Description  

(c) Arnim Eijkhoudt \<arnime _squiggly_ kpn-cert.nl\>, 2017-2019, KPN-CERT, GPLv2 license
  
Netchecker lets you offline-check a list of IP addresses and CIDRs against known AS numbers/names. Works with both IPv4 and IPv6! This tool is useful for checking of e.g. leaked/dumped IPs/CIDRs against ASNs to see if there are matches, without having to use internet sources and thereby risking the possibility of announcing your interest in the checked addresses/ranges.
  
Netchecker automatically parses the entirety of any text file (unstructured or not) for anything resembling an IPv4 address, IPv6 address or a CIDR-netblock, and will determine if any of those belong to one of the AS numbers/names you specified as keyword searches. The output will show

1) which IPs/CIDRs were found in which ASNs
2) to which exact subnet the IPs/CIDRs belong (useful for helping to determine the ownership for delegated prefixes)
3) how many IPs/CIDRs were found in the source file
4) how many of the IPs/CIDRs found in the source file were discovered in the searched ASNs
5) how many of the IPs/CIDRs found in the source file were NOT discovered in the searched ASNs
6) which of the found IPs/CIDRs from the source file were NOT discovered in the searched ASNs

# Requirements  
  
1) Python 3.x (should work with both...)
2) [required] MaxMind's GeoLite ASN databases: http://dev.maxmind.com/geoip/legacy/geolite/ (auto-download possible)
  
# Installation  
  
1) git clone https://github.com/uforia/netchecker.git

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
