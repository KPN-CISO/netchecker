#!/usr/bin/env python3

### (c) 2017 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl>, GPLv2 licensed except where
### otherwise indicated (e.g.: netaddr / MaxMind stuff).

### This product includes GeoLite data created by MaxMind, available from http://www.maxmind.com.
### You might have to change the following if MaxMind changes the filename URLs and/or schemes.
### URLs and names of GeoIP CSV files, used for grabbing the ZIP archives from the MaxMind website.
GeoIPURL='https://geolite.maxmind.com/download/geoip/database/'
GeoIPURLzip='GeoLite2-ASN-CSV.zip'
GeoIPv4='GeoLite2-ASN-Blocks-IPv4.csv'
GeoIPv6='GeoLite2-ASN-Blocks-IPv6.csv'
ASnumCache='ASnumCache.db'
ASnameCache='ASnameCache.db'
NetblockCache='NetblockCache.db'

### The 'netaddr' module can be downloaded through PyPi (pip install ...) or installed
### through your package manager of choice.
import sys
import re
import csv
import optparse
import zipfile
import os
import ipaddress
import pickle
import itertools

### Python 2/3 compatibility (urllib2 and ipaddr no longer exist in Python 3.x)
try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen
try:
    import ipaddress
except ImportError:
    print("E) Python ipaddress module is required: maybe you need to pip install ipaddress?")
    sys.exit(1)

def _is_subnet_of(a, b):
    try:
        # Always false if one is v4 and the other is v6.
        if a._version != b._version:
            raise TypeError("{a} and {b} are not of the same version")
        return (b.network_address <= a.network_address and
                b.broadcast_address >= a.broadcast_address)
    except AttributeError:
        raise TypeError("Unable to test subnet containment "
                        "between {a} and {b}")

def subnet_of(a, b):
    """Return True if this network is a subnet of other."""
    return _is_subnet_of(a, b)

def supernet_of(a, b):
    """Return True if this network is a supernet of other."""
    return _is_subnet_of(b, a)

def UpdateGeoIP(options):
    """
    Download the GeoLite IP databases from MaxMind and unpack them into the current working directory.
    This will overwrite any existing file(s) with the same name.
    """
    if options.verbose:
        print("U) Updating GeoLite ASN databases from "+GeoIPURL)
    try:
        response=urlopen(GeoIPURL+GeoIPURLzip)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    except:
        print("E) An error occurred downloading "+GeoIPURL+GeoIPURLzip)
    try:
        with open(GeoIPURLzip,'wb') as f:
            f.write(response.read())
    except IOError:
        print("E) An error occurred writing "+GeoIPURLzip+ " to disk!")
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    try:
        with zipfile.ZipFile(GeoIPURLzip,'r') as z:
            contents = z.namelist()
            for filename in contents:
                if filename.endswith(GeoIPv4):
                    with open(GeoIPv4,'wb') as f:
                        f.write(z.read(filename))
                if filename.endswith(GeoIPv6):
                    with open(GeoIPv6,'wb') as f:
                        f.write(z.read(filename))
            os.unlink(GeoIPURLzip)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
#    except:
#        print("E) An error occured unzipping "+GeoIPURLzip)
    if options.verbose:
        print("U) Update done!")

def BuildCache(options):
    """
    Build a list of IP ranges out of the MaxMind files, build a lookup dictionary and write it to disk for caching purposes
    """
    if options.verbose:
        print("U) Building the GeoLite ASN cache")
    try:
        if GeoIPv4:
            with open(GeoIPv4,'rt',encoding='iso8859-1') as f:
                IPv4ASNs=tuple(csv.reader(f))
        if GeoIPv6:
            with open(GeoIPv6,'rt',encoding='iso8859-1') as f:
                IPv6ASNs=tuple(csv.reader(f))
    except TypeError:
        ### Python 2.7 compatibility
        if GeoIPv4:
            with open(GeoIPv4,'rt') as f:
                IPv4ASNs=tuple(csv.reader(f))
        if GeoIPv6:
            with open(GeoIPv6,'rt') as f:
                IPv6ASNs=tuple(csv.reader(f))
    except IOError:
        print("E) Error opening/reading ASN file(s): "+GeoIPv4+" or "+GeoIPv6+" - try running with -u (update) option")
        sys.exit(1)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    ASnumdict={}
    ASnamedict={}
    Netblockdict={}
    if options.verbose:
        print("U) Building cache, this will take a while")
        ipv4count,ipv6count=0,0
    for line in IPv4ASNs:
        try:
            netblock,ASnum,ASname=line
            if netblock == 'network' and ASnum == 'autonomous_system_number' and ASname == 'autonomous_system_organization':
                continue
        except KeyboardInterrupt:
            print("E) CTRL-C pressed, stopping!")
            sys.exit(1)
        except:
            print("E) An error occurred parsing the IPv4ASN: "+line)
            continue
        if options.verbose:
            ipv4count+=1
            if (ipv4count%500)==0:
                sys.stdout.write('.')
                sys.stdout.flush()
        if ASname in ASnamedict:
            ASnamedict[ASname].append(netblock)
        else:
            ASnamedict[ASname]=list()
            ASnamedict[ASname].append(netblock)
        if ASnum in ASnumdict:
            ASnumdict[ASnum].append(netblock)
        else:
            ASnumdict[ASnum]=list()
            ASnumdict[ASnum].append(netblock)
        Netblockdict[netblock] = (ASnum,ASname)
    for line in IPv6ASNs:
        try:
            netblock,ASnum,ASname=line
            if netblock == 'network' and ASnum == 'autonomous_system_number' and ASname == 'autonomous_system_organization':
                continue
        except KeyboardInterrupt:
            print("E) CTRL-C pressed, stopping!")
            sys.exit(1)
        except:
            print("E) An error occurred parsing the IPv6ASN: "+IPv6ASN)
            continue
        if options.verbose:
            ipv6count+=1
            if (ipv6count%500==0):
                sys.stdout.write('.')
                sys.stdout.flush()
        if ASname in ASnamedict:
            ASnamedict[ASname].append(netblock)
        else:
            ASnamedict[ASname]=list()
            ASnamedict[ASname].append(netblock)
        if ASnum in ASnumdict:
            ASnumdict[ASnum].append(netblock)
        else:
            ASnumdict[ASnum]=list()
            ASnumdict[ASnum].append(netblock)
        Netblockdict[netblock] = (ASname,ASnum)
    if options.verbose:
        sys.stdout.write('done!\n')
        sys.stdout.flush()
    try:
        with open(ASnumCache,'wb') as f:
            pickle.dump(ASnumdict,f)
        with open(ASnameCache,'wb') as f:
            pickle.dump(ASnamedict,f)
        with open(NetblockCache,'wb') as f:
            pickle.dump(Netblockdict,f)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    except:
        print("E) An error occurred writing the cache to disk!")
        sys.exit(1)
        print("U) Successfully built the GeoLite ASN cache: "+str(ipv4count+ipv6count)+" ranges (IPv4:"+str(ipv4count)+"/IPv6:"+str(ipv6count)+")")

def CheckIPs(options,ASNs):
    """
    Check if the given filename containing IP addresses has any that belong to the generated list of netblocks
    """
    try:
        addresslist = set()
        ipv4_address = re.compile('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        ipv6_address = re.compile('(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')
        ipv4_cidr = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))")
        ipv6_cidr = re.compile('s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])?$')
        with open(options.filename) as ipfp:
            for line in ipfp.readlines():
                result1 = ipv4_address.finditer(line)
                result2 = ipv6_address.finditer(line)
                result3 = ipv4_cidr.finditer(line)
                result4 = ipv6_cidr.finditer(line)
                for ip in [line.group(0) for line in result1]:
                    addresslist.add(ip)
                for ip in [line.group(0) for line in result2]:
                    addresslist.add(ip)
                for cidr in [line.group(0) for line in result3]:
                    ip,mask=cidr.split('/')
                    if mask != '32':
                        addresslist.add(ip + '/' + mask)
                    else:
                        addresslist.add(ip)
                for cidr in [line.group(0) for line in result4]:
                    ip,mask=cidr.split('/')
                    if mask != '128':
                        addresslist.add(ip + '/' + mask)
                    else:
                        addresslist.add(ip)
        if options.verbose:
            print("I) Found " + str(len(addresslist)) + " IP addresses in file: " + options.filename)
    except IOError:
        print("E) Error opening "+options.filename+"!")
        sys.exit(1)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    if options.verbose:
        print("I) Reading GeoLite ASN caches: " + ASnameCache + ", " + ASnumCache + " and " + NetblockCache + "...")
    try:
        with open(ASnameCache, 'rb') as f:
            ASnameCacheFile = pickle.load(f)
        with open(ASnumCache, 'rb') as f:
            ASnumCacheFile = pickle.load(f)
        with open(NetblockCache, 'rb') as f:
            NetblockCacheFile = pickle.load(f)
    except FileNotFoundError:
        print("E) Not all GeoLite ASN caches were found; perhaps you need to update (-u) first?")
        sys.exit(1)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
#    except:
#        print("E) An error occurred reading the cache from disk!")
#        sys.exit(1)
    if options.verbose:
        print("I) Loaded GeoLite ASN caches!")
        print("I) Checking the list of IPs")
    else:
        print("\"IP\",\"Network\",\"ASname\"")
    output=""
    if options.verbose:
        ipcount=0
        hits=0
    ASN = '|'.join(ASNs)
    prog = re.compile(ASN,re.IGNORECASE)
    matchset = set()
    if ASN == '':
        ASN = 'all ASNs'
    if options.verbose:
        print("I) Search string: " + ASN)
    if ASN == 'all ASNs':
        # Go through the list of all netblocks and find out what the corresponding AS numbers/names are
        ASblocks = dict()
        for address in addresslist:
            if options.verbose:
                ipcount += 1
            for netblock in NetblockCacheFile.keys():
                if ipaddress.ip_network(address)._version == ipaddress.ip_network(netblock)._version:
                    if subnet_of(ipaddress.ip_network(address), (ipaddress.ip_network(netblock))):
                        ASnum, ASname = NetblockCacheFile[netblock]
                        matchset.add((ASname, address, netblock))
                        if ASname in ASblocks:
                            ASblocks[ASname].append(address)
                        else:
                            ASblocks[ASname] = list()
                            ASblocks[ASname].append(address)
                        if options.verbose:
                            hits += 1
                        else:
                            print("\"" + address + "\",\"" + netblock + "\",\"" + ASname + "\"")
    else:
        # First, build a list of the requested ASNs and their netblocks
        netblocks = dict()
        ASblocks = dict()
        for AS in ASNs:
            if AS[:2].lower() == 'as' and AS[2:] in ASnumCacheFile.keys():
                netblocks[AS] = ASnumCacheFile[AS[2:]]
            else:
                if AS in ASnumCacheFile.keys():
                    netblocks[AS] = ASnumCacheFile[AS]
                else:
                    for ASnamematch in [s for s in ASnameCacheFile.keys() if AS.lower() in s.lower()]:
                        netblocks[ASnamematch] = ASnameCacheFile[ASnamematch]
        # Now check every IP to see if it appears in one of the ASNs to search for
        for address in addresslist:
            if options.verbose:
                ipcount += 1
            for ASname in netblocks.keys():
                for netblock in netblocks[ASname]:
                    if ipaddress.ip_network(address)._version == ipaddress.ip_network(netblock)._version:
                        if subnet_of(ipaddress.ip_network(address), (ipaddress.ip_network(netblock))):
                            matchset.add((ASname, address, netblock))
                            if ASname in ASblocks:
                                ASblocks[ASname].append(address)
                            else:
                                ASblocks[ASname] = list()
                                ASblocks[ASname].append(address)
                            if options.verbose:
                                hits += 1
                            else:
                                print("\"" + address + "\",\"" + netblock + "\",\"" + ASname + "\"")
    if options.verbose:
        print("I) All done, "+str(ipcount)+" IPs checked, found "+str(hits)+" matches:")
        for ASname in ASblocks.keys():
            sys.stdout.write(ASname + ": ")
            for address in ASblocks[ASname]:
                sys.stdout.write(address + ' ')
            sys.stdout.write('\n')
            sys.stdout.flush()
    if options.verbose:
        if len(matchset) < len(addresslist):
            print("I) Found " + str(len(matchset)) + " IPs in the specified ASN search string: \"" + ASN + "\" out of " + str(len(addresslist)) + " total IP addresses.")
            if options.notfound:
                print("I) These " + str(len(addresslist) - len(matchset)) + " addresses were not matched: ")
                for ip in addresslist.difference(matchset):
                    sys.stdout.write(ip + ' ')
                sys.stdout.write('\n')
                sys.stdout.flush()
        else:
            print("I) Found all " + str(len(matchset)) + " IPs in the specified ASNs: " + ASN)

if __name__=="__main__":
    cli=optparse.OptionParser(usage="usage: %prog -f <IPFILE> [options...] <list of AS names / numbers> ...\n\nE.g.: %prog -f ips.txt AS286 'KPN B.V.' BlepTech ...")
    cli.add_option('-f','--file',dest='filename',action='store',help='[required] File with IPs to check',metavar='IPFILE')
    cli.add_option('-a','--all',dest='allasns',action='store_true',default=False,help='[optional] Find the ASNs for all IPs (warning: slow!)')
    cli.add_option('-q','--quiet',dest='verbose',action='store_false',default=True,help='[optional] Do not print progress, errors (quiet operation), CSV output format')
    cli.add_option('-u','--update',dest='update',action='store_true',default=False,help='[optional] Update and build the GeoLite ASN cache (requires an internet connection)')
    cli.add_option('-b','--build',dest='build',action='store_true',default=False,help='[optional] Build the GeoLite ASN cache (use if you downloaded the MaxMind files manually')
    cli.add_option('-n','--notfound',dest='notfound',action='store_true',default=False,help='[optional] Display the list of addresses that were not matched against the given ASNs')
    (options,ASNs)=cli.parse_args()
    if options.update:
        UpdateGeoIP(options)
        BuildCache(options)
    elif options.build:
        BuildCache(options)
    if options.filename:
        if (not options.allasns and len(ASNs)>0) or (options.allasns and not len(ASNs)>0):
            CheckIPs(options,ASNs)
        else:
            cli.print_help()
    else:
        cli.print_help()
