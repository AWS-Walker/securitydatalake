#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
sys.path.append('.')

from geolite2 import geolite2
#from user_agents import parse

print('Loading Lambda function')

reader = geolite2.reader()
geo_loc = reader.get('13.224.172.72')

try:
    geoip_city = geo_loc['city']['names']['en']
except:
    geoip_city = 'Unidentified'
try:
    geoip_country = geo_loc['country']['names']['en']
except:
    geoip_country = 'Unidentified'
try:
    geoip_lat = str(geo_loc['location']['latitude'])
    geoip_lon = str(geo_loc['location']['longitude'])
except:
    geoip_lat = '0'
    geoip_lon = '0'

print(geoip_country)
print(geoip_city)

#print('Successfully processed {} records.'.format(len(event['records'])))

