#!/usr/bin/env python

### (c) 2017 Arnim Eijkhoudt <arnime _squigglything_ kpn-cert.nl>, GPLv2 licensed except where
### otherwise indicated (e.g.: netaddr / MaxMind stuff).

### This product includes GeoLite data created by MaxMind, available from http://www.maxmind.com.
### You might have to change the following if MaxMind changes the filename URLs and/or schemes.
### URLs and names of GeoIP CSV files, used for grabbing the ZIP archives from the MaxMind website.
GeoIPURL='http://download.maxmind.com/download/geoip/database/asnum/'
GeoIPURLzip='GeoIPASNum2.zip'
GeoIPv6URLzip='GeoIPASNum2v6.zip'
GeoIP='GeoIPASNum2.csv'
GeoIPv6='GeoIPASNum2v6.csv'
GeoCache='GeoCache.db'

### The 'netaddr' module can be downloaded through PyPi (pip install ...) or installed
### through your package manager of choice.
import sys,re,csv,optparse,zipfile,os,netaddr,pickle

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
			with open(GeoIP,'wb') as f:
				f.write(z.read(GeoIP))
				os.unlink(GeoIPURLzip)
	except KeyboardInterrupt:
		print("E) CTRL-C pressed, stopping!")
		sys.exit(1)
	except:
		print("E) An error occured unzipping "+GeoIPURLzip)
	try:
		response=urlopen(GeoIPURL+GeoIPv6URLzip)
	except KeyboardInterrupt:
		print("E) CTRL-C pressed, stopping!")
		sys.exit(1)
	except:
		print("E) An error occurred downloading "+GeoIPURL+GeoIPv6URLzip)
	try:
		with open(GeoIPv6URLzip,'wb') as f:
			f.write(response.read())
	except IOError:
		print("E) An error occurred writing "+GeoIPv6URLzip+ " to disk!")
	except KeyboardInterrupt:
		print("E) CTRL-C pressed, stopping!")
		sys.exit(1)
	try:
		with zipfile.ZipFile(GeoIPv6URLzip,'r') as z:
			with open(GeoIPv6,'wb') as f:
				f.write(z.read(GeoIPv6))
				os.unlink(GeoIPv6URLzip)
	except KeyboardInterrupt:
		print("E) CTRL-C pressed, stopping!")
		sys.exit(1)
	except:
		print("E) An error occured unzipping "+GeoIPv6URLzip)
	if options.verbose:
		print("U) Update done!")

def IntIPtoStr(integervalue):
	"""
	Convert an integer-formatted IPv4 address into a tuple which can be converted into dot notation
	"""
	return str(netaddr.IPAddress(integervalue))

def StrIPtoInt(stringvalue):
	"""
	Convert a string-formatted IPv4 address back into an integer value
	"""
	return int(netaddr.IPAddress(stringvalue))

def BuildCache(options):
	"""
	Build a list of IP ranges out of the MaxMind files, build a lookup dictionary and write it to disk for caching purposes
	"""
	if options.verbose:
		print("U) Building the GeoLite ASN cache")
	try:
		if GeoIP:
			with open(GeoIP,'rt',encoding='iso8859-1') as f:
				IPv4ASNs=tuple(csv.reader(f))
		if GeoIPv6:
			with open(GeoIPv6,'rt',encoding='iso8859-1') as f:
				IPv6ASNs=tuple(csv.reader(f))
	except TypeError:
		### Python 2.7 compatibility
		if GeoIP:
			with open(GeoIP,'rt') as f:
				IPv4ASNs=tuple(csv.reader(f))
		if GeoIPv6:
			with open(GeoIPv6,'rt') as f:
				IPv6ASNs=tuple(csv.reader(f))
	except IOError:
		print("E) Error opening/reading ASN file(s): "+GeoIP+" or "+GeoIPv6+" - try running with -u (update) option")
		sys.exit(1)
	except KeyboardInterrupt:
		print("E) CTRL-C pressed, stopping!")
		sys.exit(1)
	netblockdict={}
	if options.verbose:
		print("U) Building netblock cache, this will take a while")
		ipv4count,ipv6count=0,0
	for line in IPv4ASNs:
		try:
			netblockstartint,netblockendint,ASname=line
		except KeyboardInterrupt:
			print("E) CTRL-C pressed, stopping!")
			sys.exit(1)
		except:
			print("E) An error occurred parsing the IPv4ASN: "+line)
			next
		if options.verbose:
			ipv4count+=1
			if (ipv4count%500)==0:
				sys.stdout.write('.')
				sys.stdout.flush()
		netblockstart=int(netblockstartint)
		netblockend=int(netblockendint)
		netblock=(netblockstart,netblockend)
		if ASname in netblockdict:
			netblockdict[ASname].append(netblock)
		else:
			netblockdict[ASname]=list()
			netblockdict[ASname].append(netblock)
	for line in IPv6ASNs:
		try:
			ASname,netblockstartaddress,netblockendaddress,netmask=line
		except KeyboardInterrupt:
			print("E) CTRL-C pressed, stopping!")
			sys.exit(1)
		except:
			print("E) An error occurred parsing the IPv6ASN: "+IPv6ASN)
			next
		if options.verbose:
			ipv6count+=1
			if (ipv6count%500==0):
				sys.stdout.write('.')
				sys.stdout.flush()
		netblock=(netblockstartaddress,netmask)
		if ASname in netblockdict:
			netblockdict[ASname].append(netblock)
		else:
			netblockdict[ASname]=list()
			netblockdict[ASname].append(netblock)
	try:
		with open(GeoCache,'wb') as f:
			pickle.dump(netblockdict,f)
	except KeyboardInterrupt:
		print("E) CTRL-C pressed, stopping!")
		sys.exit(1)
	except:
		print("E) An error occurred writing the cache to disk!")
		sys.exit(1)
	if options.verbose:
		sys.stdout.write('\n')
		sys.stdout.flush()
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
					addresslist.add(('ipv4', ip, '32'))
				for ip in [line.group(0) for line in result2]:
					addresslist.add(('ipv6', ip, '128'))
				for cidr in [line.group(0) for line in result3]:
					ip,mask=cidr.split('/')
					addresslist.add(('ipv4', ip, mask))
				for cidr in [line.group(0) for line in result4]:
					ip,mask=cidr.split('/')
					addresslist.add(('ipv6', ip, mask))
		if options.verbose:
			print("I) Found " + str(len(addresslist)) + " IP addresses in file: " + options.filename)
	except IOError:
		print("E) Error opening "+options.filename+"!")
		sys.exit(1)
	except KeyboardInterrupt:
		print("E) CTRL-C pressed, stopping!")
		sys.exit(1)
	if options.verbose:
		print("I) Reading GeoLite ASN cache")
	try:
		with open(GeoCache,'rb') as f:
			netblockdict=pickle.load(f)
	except KeyboardInterrupt:
		print("E) CTRL-C pressed, stopping!")
		sys.exit(1)
	except:
		print("E) An error occurred reading the cache from disk!")
		sys.exit(1)
	if options.verbose:
		print("I) Loaded GeoLite ASN cache!")
		print("I) Checking the list of IPs")
	else:
		print("\"IP\",\"Network\",\"ASname\"")
	output=""
	if options.verbose:
		ipcount=0
		hits=0
	ASN='|'.join(ASNs)
	if ASN=='':
		ASN='.*'
	if options.verbose:
		sys.stdout.write("I) Search string: "+ASN+' ')
		sys.stdout.flush()
	prog=re.compile(ASN,re.IGNORECASE)
	matchset=set()
	for key in netblockdict:
		if prog.search(key):
			# Build netblocks
			netblocks=[]
			for range in netblockdict[key]:
				try:
					version=ipaddress.ip_address(unicode(IntIPtoStr(range[0]))).version
				except NameError:
					version=ipaddress.ip_address(IntIPtoStr(range[0])).version
				except KeyboardInterrupt:
					print("E) CTRL-C pressed, stopping!")
					sys.exit(1)
				if version==4:
					netblocks.append((IntIPtoStr(range[0]),IntIPtoStr(range[1])))
				if version==6:
					netblocks.append((range[0],str([netaddr.IPNetwork(str(range[0]+'/'+range[1]))][0])))
			for iptype,ip,mask in addresslist:
				try:
					ip=unicode(ip)
				except NameError:
					pass
				except KeyboardInterrupt:
					print("E) CTRL-C pressed, stopping!")
					sys.exit(1)
				try:
					ipversion=ipaddress.ip_address(ip).version
				except ValueError:
					continue
				except KeyboardInterrupt:
					print("E) CTRL-C pressed, stopping!")
					sys.exit(1)
				if options.verbose:
					ipcount+=1
					if (ipcount%100)==0:
						sys.stdout.write('.')
						sys.stdout.flush()
				for netblock in netblocks:
					try:
						netblockstart=netblock[0]
						netblockstart=unicode(netblockstart)
					except NameError:
						pass
					except KeyboardInterrupt:
						print("E) CTRL-C pressed, stopping!")
						sys.exit(1)
					try:
						netblockversion=ipaddress.ip_address(netblockstart).version
					except ValueError:
						continue
					except KeyboardInterrupt:
						print("E) CTRL-C pressed, stopping!")
						sys.exit(1)
					if ipversion==4 and netblockversion==4:
						if StrIPtoInt(ip) > StrIPtoInt(netblock[0]) and StrIPtoInt(ip) < StrIPtoInt(netblock[1]):
							if options.verbose:
								output+="!) "+ip+"/"+mask+" --> "+netblock[0]+"-"+netblock[1]+" ("+key+")\n"
								hits+=1
							else:
								output+="\""+ip+"/"+mask+"\",\""+netblock[0]+"-"+netblock[1]+"\",\""+key+"\"\n"
							matchset.add(('ipv4', ip, '32'))
					elif ipversion==6 and netblockversion==6:
						if netaddr.IPAddress(ip,6) in netaddr.IPNetwork(netblock[0],netblock[1],6):
							if options.verbose:
								output+="!) "+ip+"/"+mask+" --> "+netblock[1]+" ("+key+")\n"
								hits+=1
							else:
								output+="\""+ip+"/"+mask+"\",\""+netblock[1]+"\",\""+key+"\"\n"
							matchset.add(('ipv6', ip, '128'))
	if options.verbose:
		sys.stdout.write('\n')
		sys.stdout.flush()
	if output:
		sys.stdout.write(output)
		sys.stdout.flush()
	#if options.verbose:
	#	print("I) All done, "+str(ipcount)+" IPs checked, found "+str(hits)+" matches")
	if options.verbose:
		if len(matchset) < len(addresslist):
			print("I) Found " + str(len(matchset)) + " IPs in the specified ASN search string: \"" + ASN + "\" out of " + str(len(addresslist)) + " total IP addresses.")
			print("I) These IP addresses were not matched:")
			for ip in addresslist.difference(matchset):
				print("I) " + ip[1] + "/" + ip[2])
		else:
			print("I) Found all " + str(len(matchset)) + " IPs in the specified ASNs: " + ASN)

if __name__=="__main__":
	cli=optparse.OptionParser(usage="usage: %prog -f <IPFILE> [options...] <list of AS names / numbers> ...\n\nE.g.: %prog -f ips.txt AS286 'KPN B.V.' BlepTech ...")
	cli.add_option('-f','--file',dest='filename',action='store',help='[required] File with IPs to check',metavar='IPFILE')
	cli.add_option('-a','--all',dest='allasns',action='store_true',default=False,help='[optional] Find the ASNs for all IPs (warning: slow!)')
	cli.add_option('-q','--quiet',dest='verbose',action='store_false',default=True,help='[optional] Do not print progress, errors (quiet operation), CSV output format')
	cli.add_option('-u','--update',dest='update',action='store_true',default=False,help='[optional] Update and build the GeoLite ASN cache (requires an internet connection)')
	cli.add_option('-b','--build',dest='build',action='store_true',default=False,help='[optional] Build the GeoLite ASN cache (use if you downloaded the MaxMind files manually')
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
