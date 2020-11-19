#!/usr/bin/python3

import csv
#from pprint import pprint
#import ipaddress
import requests
from io import BytesIO, StringIO
import zipfile
from os import makedirs
import socket
import struct

LicenseKey = '' #YOUR_GEOLITE2_LICENSE_CODE_HERE

DLlink_DB     = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=%s&suffix=zip'%(LicenseKey)
DLlink_SHA256 = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=%s&suffix=zip.sha256'%(LicenseKey)

DLPath = '/usr/share/xt_geoip'
#DLPath = '.'




# Get sha256sum of db zip file
zip_sha256sum = requests.get(DLlink_SHA256).content.strip().split()[0].decode()

# Check if current db is recent
# make if not exist
with open('%s/db.sha256'%(DLPath), 'a+') as f:
    pass

with open('%s/db.sha256'%(DLPath), 'r+') as f:
    oldsum = f.read()
    if oldsum != zip_sha256sum:
        f.seek(0)
        f.write(zip_sha256sum)
    else:
        print("Latest DB!")
        exit(0)


# Download, Parse, Save
db_zip = zipfile.ZipFile(BytesIO(requests.get(DLlink_DB).content))

ipv4_csv = next(filter(lambda x:'IPv4' in x, db_zip.namelist()))
ipv6_csv = next(filter(lambda x:'IPv6' in x, db_zip.namelist()))
countrycode_csv = next(filter(lambda x:'en' in x, db_zip.namelist()))

countrycode = dict()
ipdict_ipv4 = dict()
ipdict_ipv6 = dict()

isocode = ''


# Get ISO code of countryid
with StringIO(db_zip.read(countrycode_csv).decode('utf-8')) as f:
    i = 1
    f.readline()
    r = csv.reader(f)
    for line in r:
        if line[4] == '':
            isocode = 'A'+str(i)
            i = i + 1
        else:
            isocode = line[4]
        countrycode[line[0]] = isocode

for isocode in countrycode.values():
    ipdict_ipv4[isocode] = list()
    ipdict_ipv6[isocode] = list()


with StringIO(db_zip.read(ipv4_csv).decode('utf-8')) as f:
    f.readline()
    r = csv.reader(f)
    for line in r:
        if line[1] != '':
            isocode=countrycode[line[1]]
        elif line [2] != '':
            isocode=countrycode[line[2]]
        else:
            continue
        ipdict_ipv4[isocode].append(line[0])


with StringIO(db_zip.read(ipv6_csv).decode('utf-8')) as f:
    f.readline()
    r = csv.reader(f)
    for line in r:
        if line[1] != '':
            isocode=countrycode[line[1]]
        elif line [2] != '':
            isocode=countrycode[line[2]]
        else:
            continue
        ipdict_ipv6[isocode].append(line[0])


# Convert CIDR address (ip/netmask) range to integer pair (start, end)
def CIDR2intrange_ipv4(CIDR):
    ip, subnetmask = CIDR.split('/')
    subnetmask = int(subnetmask)
    inv_mask = 32 - subnetmask
    #start_addr = int(ipaddress.IPv4Address(ip)) & (-1 << inv_mask)
    start_addr = socket.inet_pton(socket.AF_INET, ip)
    end_addr = (int.from_bytes(start_addr, 'big') | (2 ** inv_mask - 1)).to_bytes(4, 'big')
    return start_addr, end_addr

def CIDR2intrange_ipv6(CIDR):
    ip, subnetmask = CIDR.split('/')
    subnetmask = int(subnetmask)
    inv_mask = 128 - subnetmask
    #start_addr = int(ipaddress.IPv6Address(ip)) & (-1 << inv_mask)
    start_addr = socket.inet_pton(socket.AF_INET6, ip)
    end_addr = (int.from_bytes(start_addr, 'big') | (2 ** inv_mask - 1)).to_bytes(16, 'big')
    return start_addr, end_addr

def BE2LE_ipv4(byteobj):
    int_val = struct.unpack("<L", byteobj)[0]
    return struct.pack('>L', int_val)

def BE2LE_ipv6(byteobj):
    a,b,c,d = struct.unpack("<LLLL", byteobj)
    return struct.pack(">LLLL", a,b,c,d)


try:
    import apt
    needBE = float(apt.Cache()['xtables-addons-common'].versions.keys()[0].split('-')[0]) <= 3.0
except:
    needBE = True

#for xtables-addons-common package's version <=3.0, we need to store both big endian and little endian files
if needBE:
    makedirs("%s/BE"%(DLPath), exist_ok=True)
    makedirs("%s/LE"%(DLPath), exist_ok=True)

    # Write Big Endian files
    for isocode in ipdict_ipv4:
        with open("%s/BE/%s.iv4"%(DLPath, isocode), 'wb') as f:
            for CIDR in ipdict_ipv4[isocode]:
                start_addr, end_addr = CIDR2intrange_ipv4(CIDR)
                f.write(start_addr)
                f.write(end_addr)

    for isocode in ipdict_ipv6:
        with open("%s/BE/%s.iv6"%(DLPath, isocode), 'wb') as f:
            for CIDR in ipdict_ipv6[isocode]:
                start_addr, end_addr = CIDR2intrange_ipv6(CIDR)
                f.write(start_addr)
                f.write(end_addr)


    # Write Little Endian files
    for isocode in ipdict_ipv4:
        with open("%s/LE/%s.iv4"%(DLPath, isocode), 'wb') as f:
            for CIDR in ipdict_ipv4[isocode]:
                start_addr, end_addr = CIDR2intrange_ipv4(CIDR)
                f.write(BE2LE_ipv4(start_addr))
                f.write(BE2LE_ipv4(end_addr))

    for isocode in ipdict_ipv6:
        with open("%s/LE/%s.iv6"%(DLPath, isocode), 'wb') as f:
            for CIDR in ipdict_ipv6[isocode]:
                start_addr, end_addr = CIDR2intrange_ipv6(CIDR)
                f.write(BE2LE_ipv6(start_addr))
                f.write(BE2LE_ipv6(end_addr))

else:
    for isocode in ipdict_ipv4:
        with open("%s/%s.iv4"%(DLPath, isocode), 'wb') as f:
            for CIDR in ipdict_ipv4[isocode]:
                start_addr, end_addr = CIDR2intrange_ipv4(CIDR)
                f.write(start_addr)
                f.write(end_addr)

    for isocode in ipdict_ipv6:
        with open("%s/%s.iv6"%(DLPath, isocode), 'wb') as f:
            for CIDR in ipdict_ipv6[isocode]:
                start_addr, end_addr = CIDR2intrange_ipv6(CIDR)
                f.write(start_addr)
                f.write(end_addr)


print("Geoip database update done!")
