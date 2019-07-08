#!/usr/bin/env python3

# (c) 2017 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl>, GPLv2
# licensed except where otherwise indicated (e.g.: netaddr / MaxMind stuff).

# This product includes GeoLite data created by MaxMind, available from
# http://www.maxmind.com. You might have to change the following if
# MaxMind changes the filename URLs and/or schemes. URLs and names of GeoIP
# CSV files, used for grabbing the ZIP archives from the MaxMind website.

import sys
import re
import csv
import optparse
import zipfile
import os
import ipaddress
import pickle
import bisect
from urllib.request import urlopen

GeoIPURL = 'https://geolite.maxmind.com/download/geoip/database/'
GeoIPURLzip = 'GeoLite2-ASN-CSV.zip'
GeoIPv4 = 'GeoLite2-ASN-Blocks-IPv4.csv'
GeoIPv6 = 'GeoLite2-ASN-Blocks-IPv6.csv'
ASnumCache = 'ASnumCache.db'
ASnameCache = 'ASnameCache.db'
NetblockCache = 'NetblockCache.db'


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


def UpdateGeoIP(options):
    """
    Download the GeoLite IP databases from MaxMind and unpack them into
    the current working directory. This will overwrite any existing
    file(s) with the same name.
    """
    if options.verbose:
        print("U) Updating GeoLite ASN databases from " + GeoIPURL)
    try:
        response = urlopen(GeoIPURL+GeoIPURLzip)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    try:
        with open(GeoIPURLzip, 'wb') as f:
            f.write(response.read())
    except IOError:
        print("E) An error occurred writing " + GeoIPURLzip + " to disk!")
        sys.exit(1)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    try:
        with zipfile.ZipFile(GeoIPURLzip, 'r') as z:
            contents = z.namelist()
            for filename in contents:
                if filename.endswith(GeoIPv4):
                    with open(GeoIPv4, 'wb') as f:
                        f.write(z.read(filename))
                if filename.endswith(GeoIPv6):
                    with open(GeoIPv6, 'wb') as f:
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
    Build a list of IP ranges out of the MaxMind files, build a
    lookup dictionary and write it to disk for caching purposes.
    """
    if options.verbose:
        print("U) Building the GeoLite ASN cache")
    try:
        if GeoIPv4:
            with open(GeoIPv4, 'rt', encoding='iso8859-1') as f:
                IPv4ASNs = tuple(csv.DictReader(f))
        if GeoIPv6:
            with open(GeoIPv6, 'rt', encoding='iso8859-1') as f:
                IPv6ASNs = tuple(csv.DictReader(f))
    except IOError:
        print("E) Error opening/reading ASN file(s): " + GeoIPv4 +
              " or "+GeoIPv6+" - try running with -u (update) " +
              "option")
        sys.exit(1)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    ASnumdict = {}
    ASnamedict = {}
    net4_records = []
    net4_ranges = []
    net6_records = []
    net6_ranges = []
    if options.verbose:
        print("U) Building cache, this will take a while")
        ipv4count, ipv6count = 0, 0
    for record in IPv4ASNs:
        try:
            netblock = record['network']
            ASnum = record['autonomous_system_number']
            ASname = record['autonomous_system_organization']
        except KeyboardInterrupt:
            print("E) CTRL-C pressed, stopping!")
            sys.exit(1)
        except ValueError:
            print("E) An error occurred parsing the IPv4ASN: "+record)
            continue
        if options.verbose:
            ipv4count += 1
            if (ipv4count % 500) == 0:
                sys.stdout.write('.')
                sys.stdout.flush()
        if ASname in ASnamedict.keys():
            ASnamedict[ASname].append(netblock)
        else:
            ASnamedict[ASname] = list()
            ASnamedict[ASname].append(netblock)
        if ASnum in ASnumdict.keys():
            ASnumdict[ASnum].append(netblock)
        else:
            ASnumdict[ASnum] = list()
            ASnumdict[ASnum].append(netblock)
        net4 = ipaddress.IPv4Network(netblock)
        net4_records.append(record)
        min_addr = net4.network_address
        max_addr = min_addr + net4.num_addresses
        net4_ranges.extend([min_addr.packed, max_addr.packed])
    for i in range(len(net4_ranges)-1):
        assert net4_ranges[i] <= net4_ranges[i+1]
    if options.verbose:
        sys.stdout.write('\n')
        sys.stdout.flush()
        print("IPv4: " + str(len(net4_records)) + " records / " +
              str(len(net4_ranges)) + " ranges!")
    for record in IPv6ASNs:
        try:
            netblock = record['network']
            ASnum = record['autonomous_system_number']
            ASname = record['autonomous_system_organization']
        except KeyboardInterrupt:
            print("E) CTRL-C pressed, stopping!")
            sys.exit(1)
        except ValueError:
            print("E) An error occurred parsing the IPv6ASN: "+record)
            continue
        if options.verbose:
            ipv6count += 1
            if (ipv6count % 500 == 0):
                sys.stdout.write('.')
                sys.stdout.flush()
        if ASname in ASnamedict.keys():
            ASnamedict[ASname].append(netblock)
        else:
            ASnamedict[ASname] = list()
            ASnamedict[ASname].append(netblock)
        if ASnum in ASnumdict.keys():
            ASnumdict[ASnum].append(netblock)
        else:
            ASnumdict[ASnum] = list()
            ASnumdict[ASnum].append(netblock)
        net6 = ipaddress.IPv6Network(netblock)
        net6_records.append(record)
        min_addr = net6.network_address
        max_addr = min_addr + net6.num_addresses
        net6_ranges.extend([min_addr.packed, max_addr.packed])
    for i in range(len(net6_ranges)-1):
        assert net6_ranges[i] <= net6_ranges[i+1]
    if options.verbose:
        sys.stdout.write('\n')
        sys.stdout.flush()
        print("IPv6: " + str(len(net6_records)) + " records / " +
              str(len(net6_ranges)) + " ranges!")
    try:
        with open(ASnumCache, 'wb') as f:
            pickle.dump(ASnumdict, f)
        with open(ASnameCache, 'wb') as f:
            pickle.dump(ASnamedict, f)
        with open(NetblockCache, 'wb') as f:
            pickle.dump((net4_records,
                         net4_ranges,
                         net6_records,
                         net6_ranges), f)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    except IOError:
        print("E) An error occurred writing the cache to disk!")
        sys.exit(1)
        print("U) Successfully built the GeoLite ASN cache: " +
              str(ipv4count+ipv6count)+" ranges (IPv4:" +
              str(ipv4count)+"/IPv6:"+str(ipv6count)+")")


def CheckIPs(options, ASNs):
    """
    Check if the given filename containing IP addresses has any
    that belong to the generated list of netblocks.
    """
    try:
        addresslist = set()
        ipv4_address = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        ipv6_address = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]'
                                  r'{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-'
                                  r'9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4'
                                  r'}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA'
                                  r'-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1'
                                  r',4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-f'
                                  r'A-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){'
                                  r'1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a'
                                  r'-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:('
                                  r'(:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-'
                                  r'fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-'
                                  r'F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(fff'
                                  r'f(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0'
                                  r'-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}('
                                  r'25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-'
                                  r'9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-'
                                  r'5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.'
                                  r'){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){'
                                  r'0,1}[0-9]))')
        ipv4_cidr = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3"
                               r"}/\d{1,2}(?!\d|(?:\.\d))")
        ipv6_cidr = re.compile(r's*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{'
                               r'1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A'
                               r'-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]'
                               r'?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})'
                               r'|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-F'
                               r'a-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd'
                               r'|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d'
                               r')){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:['
                               r'0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1'
                               r',4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.('
                               r'25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|'
                               r'(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{'
                               r'1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:('
                               r'(25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]'
                               r'|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A'
                               r'-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1'
                               r',5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5'
                               r']|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]'
                               r'd|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{'
                               r'1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|(('
                               r':[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4'
                               r']d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|['
                               r'1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4'
                               r'}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25'
                               r'[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2['
                               r'0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*\/'
                               r'([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])?$')
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
                    ip, mask = cidr.split('/')
                    if mask != '32':
                        addresslist.add(ip + '/' + mask)
                    else:
                        addresslist.add(ip)
                for cidr in [line.group(0) for line in result4]:
                    ip, mask = cidr.split('/')
                    if mask != '128':
                        addresslist.add(ip + '/' + mask)
                    else:
                        addresslist.add(ip)
        if options.verbose:
            print("I) Found " + str(len(addresslist)) +
                  " IP addresses in file: " + options.filename)
    except IOError:
        print("E) Error opening "+options.filename+"!")
        sys.exit(1)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    try:
        ASN = '|'.join(ASNs)
        if ASN == '':
            if options.verbose:
                print("I) Reading GeoLite ASN cache: " + NetblockCache +
                      "...")
            with open(NetblockCache, 'rb') as f:
                net4_records, net4_ranges, net6_records, net6_ranges = \
                     pickle.load(f)
        else:
            if options.verbose:
                print("I) Reading GeoLite ASN caches: " +
                      ASnameCache + " and " + ASnumCache + "...")
            with open(ASnameCache, 'rb') as f:
                ASnameCacheFile = pickle.load(f)
            with open(ASnumCache, 'rb') as f:
                ASnumCacheFile = pickle.load(f)
    except FileNotFoundError:
        print("E) Not all GeoLite ASN caches were found; perhaps you need " +
              "to update (-u) first?")
        sys.exit(1)
    except KeyboardInterrupt:
        print("E) CTRL-C pressed, stopping!")
        sys.exit(1)
    except IOError:
        print("E) An error occurred reading the cache from disk!")
        sys.exit(1)
    if options.verbose:
        print("I) Loaded GeoLite ASN caches!")
        print("I) Checking the list of IPs")
    else:
        print("\"IP\",\"Network\",\"ASname\"")
    if options.verbose:
        ipcount = 0
        hits = 0
    matchset = set()
    if ASN == '':
        ASN = 'all ASNs'
    if options.verbose:
        print("I) Search string: " + ASN)
    if ASN == 'all ASNs':
        # Go through the list of all netblocks and find out what the
        # corresponding AS numbers/names are
        ASblocks = dict()
        for address in addresslist:
            if options.verbose:
                sys.stdout.write('.')
                sys.stdout.flush()
                ipcount += 1
            if '/' in address:
                ip = ipaddress.ip_address(address.split('/')[0])
            else:
                ip = ipaddress.ip_address(address)
            if ip.version == 4:
                ip = ipaddress.IPv4Address(ip)
                net_idx = bisect.bisect(net4_ranges, ip.packed)
                try:
                    net_record = net4_records[net_idx//2]
                except IndexError:
                    sys.stdout.write('x')
                net = ipaddress.IPv4Network(net_record['network'])
                ASname = net_record['autonomous_system_organization']
                ASnum = net_record['autonomous_system_number']
                if ip in net:
                    matchset.add(address)
                    if ASname in ASblocks:
                        ASblocks[ASname].append(address)
                    else:
                        ASblocks[ASname] = list()
                        ASblocks[ASname].append(address)
                    if options.verbose:
                        hits += 1
                    else:
                        print("\"" + str(ip) + "\",\"" +
                              str(net) + "\",\"" + ASname + "\",\"AS" +
                              ASnum + "\"")
            elif ip.version == 6:
                ip = ipaddress.IPv6Address(address)
                net_idx = bisect.bisect(net6_ranges, ip.packed)
                try:
                    net_record = net4_records[net_idx//2]
                except IndexError:
                    sys.stdout.write('x')
                net = ipaddress.IPv6Network(net_record['network'])
                ASname = net_record['autonomous_system_organization']
                ASnum = net_record['autonomous_system_number']
                if ip in net:
                    matchset.add(address)
                    if ASname in ASblocks:
                        ASblocks[ASname].append(address)
                    else:
                        ASblocks[ASname] = list()
                        ASblocks[ASname].append(address)
                    if options.verbose:
                        hits += 1
                    else:
                        print("\"" + str(ip) + "\",\"" +
                              str(net) + "\",\"" + ASname + "\",\"AS" +
                              ASnum + "\"")
        if options.verbose:
            sys.stdout.write('\n')
            sys.stdout.flush()
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
                    filtered_list = (s for s in ASnameCacheFile.keys()
                                     if AS.lower() in s.lower())
                    for ASnamematch in filtered_list:
                        netblocks[ASnamematch] = ASnameCacheFile[ASnamematch]
        # Now check every IP to see if it appears in one of the search ASNs.
        for address in addresslist:
            if options.verbose:
                ipcount += 1
            for ASname in netblocks.keys():
                for netblock in netblocks[ASname]:
                    if ipaddress.ip_network(address)._version ==\
                       ipaddress.ip_network(netblock)._version:
                        if subnet_of(ipaddress.ip_network(address),
                                     (ipaddress.ip_network(netblock))):
                            matchset.add((ASname, address, netblock))
                            if ASname in ASblocks:
                                ASblocks[ASname].append(address)
                            else:
                                ASblocks[ASname] = list()
                                ASblocks[ASname].append(address)
                            if options.verbose:
                                hits += 1
                            else:
                                print("\"" + address + "\",\"" +
                                      netblock + "\",\"" + ASname + "\"")
    if options.verbose:
        print("I) All done, "+str(ipcount) +
              " IPs checked, found "+str(hits)+" matches:")
        for ASname in ASblocks.keys():
            sys.stdout.write(ASname + ": ")
            for address in ASblocks[ASname]:
                sys.stdout.write(address + ' ')
            sys.stdout.write('\n')
            sys.stdout.flush()
    if options.verbose:
        if len(matchset) < len(addresslist):
            print("I) Found " + str(len(matchset)) +
                  " IPs in the specified ASN search string: \"" +
                  ASN + "\" out of " + str(len(addresslist)) +
                  " total IP addresses.")
            if options.notfound:
                print("I) These " + str(len(addresslist) -
                                        len(matchset)) +
                      " addresses were not matched: ")
                for ip in addresslist.difference(matchset):
                    sys.stdout.write(ip + ' ')
                sys.stdout.write('\n')
                sys.stdout.flush()
        else:
            print("I) Found all " + str(len(matchset)) +
                  " IPs in the specified ASNs: " + ASN)


if __name__ == "__main__":
    cli = optparse.OptionParser(usage="usage: %prog -f <IPFILE> [options...] "
                                "<list of AS names / numbers> ...\n\nE.g.: "
                                "%prog -f ips.txt AS286 'KPN B.V.' BlepTech"
                                " ...")
    cli.add_option('-f', '--file', dest='filename', action='store',
                   help='[required] File with IPs to check', metavar='IPFILE')
    cli.add_option('-a', '--all', dest='allasns', action='store_true',
                   default=False, help='[optional] Find the ASNs for all IPs'
                   ' (warning: slow!)')
    cli.add_option('-q', '--quiet', dest='verbose', action='store_false',
                   default=True, help='[optional] Do not print progress, '
                   'errors (quiet operation), CSV output format')
    cli.add_option('-u', '--update', dest='update', action='store_true',
                   default=False, help='[optional] Update and build the '
                   'GeoLite ASN cache (requires an internet connection)')
    cli.add_option('-b', '--build', dest='build', action='store_true',
                   default=False, help='[optional] Build the GeoLite ASN'
                   ' cache (use if you downloaded the MaxMind files manually')
    cli.add_option('-n', '--notfound', dest='notfound', action='store_true',
                   default=False, help='[optional] Display the list of '
                   'addresses that were not matched against the given ASNs')
    (options, ASNs) = cli.parse_args()
    if options.update:
        UpdateGeoIP(options)
        BuildCache(options)
    elif options.build:
        BuildCache(options)
    if options.filename:
        if (not options.allasns and len(ASNs) > 0) or\
           (options.allasns and not len(ASNs) > 0):
            CheckIPs(options, ASNs)
        else:
            cli.print_help()
    else:
        cli.print_help()
