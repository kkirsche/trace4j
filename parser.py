# -*- coding: utf-8 -*-

"""
Run traceroute
"""

import json
import re
import logging
from ipaddress import ip_network
from subprocess import run, PIPE


class Traceroute(object):
    """
    Traceroute instance.
    """
    def __init__(self, cidr):
        super(self.__class__, self).__init__()
        self.cidr = ip_network(cidr)
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.no_geo = True

    def traceroute(self):
        """
        Instead of running the actual traceroute command, we will fetch
        standard traceroute results from several publicly available webpages
        that are listed at traceroute.org. For each hop, we will then attach
        geolocation information to it.
        """
        self.logger.info("cidr_network={cidr}".format(cidr=str(self.cidr)))

        if self.cidr.prefixlen == 32:
            hosts = [self.cidr.network_address]
        else:
            hosts = list(self.cidr.hosts())

        for host in hosts:
            self.logger.info('cmd=traceroute {host} action=starting'.format(
                host=host))
            tr = run(['traceroute', str(host)], stdout=PIPE, stderr=PIPE)
            self.logger.info('cmd=traceroute {host} action=complete'.format(
                host=host))
            tr_out = tr.stdout.decode('utf-8')
            # hop_num, hosts
            hops = self.get_hops(tr_out)

            # hop_num, hostname, ip_address, rtt
            hops = self.get_formatted_hops(hops)

            if not self.no_geo:
                # hop_num, hostname, ip_address, rtt, latitude, longitude
                hops = self.get_geocoded_hops(hops)

            for hop in hops:
                self.logger.info(('hop_number={hop_num} hostname={hostname} '
                                  'ip_address={ip} rtt={rtt}').format(
                                      hop_num=hop['hop_num'],
                                      hostname=hop['hostname'],
                                      ip=hop['ip_address'],
                                      rtt=hop['rtt']))

    def get_hops(self, traceroute):
        """
        Returns hops from traceroute output in an array of dicts each
        with hop number and the associated hosts data.
        """
        hops = []
        regex = r'^(?P<hop_num>\d+)(?P<hosts>.*?)$'
        lines = traceroute.split("\n")
        for line in lines:
            line = line.strip()
            hop = {}
            if not line:
                continue
            try:
                hop = re.match(regex, line).groupdict()
            except AttributeError:
                continue
            self.logger.debug(hop)
            hops.append(hop)
        return hops

    def get_formatted_hops(self, hops):
        """
        Hosts data from get_hops() is represented in a single string.
        We use this function to better represent the hosts data in a dict.
        """
        formatted_hops = []
        regex = r'(?P<h>[\w.-]+) \((?P<i>[\d.]+)\) (?P<r>\d{1,4}.\d{1,4} ms)'
        for hop in hops:
            hop_num = int(hop['hop_num'].strip())
            hosts = hop['hosts'].replace("  ", " ").strip()
            # Using re.findall(), we split the hosts, then for each host,
            # we store a tuple of hostname, IP address and the first RTT.
            hosts = re.findall(regex, hosts)
            for host in hosts:
                hop_context = {
                    'hop_num': hop_num,
                    'hostname': host[0],
                    'ip_address': host[1],
                    'rtt': host[2],
                }
                self.logger.debug(hop_context)
                formatted_hops.append(hop_context)
        return formatted_hops

    def get_geocoded_hops(self, hops):
        """
        Returns hops from get_formatted_hops() with geolocation information
        for each hop.
        """
        geocoded_hops = []
        for hop in hops:
            ip_address = hop['ip_address']
            location = None
            if ip_address in self.locations:
                location = self.locations[ip_address]
            else:
                location = self.get_location(ip_address)
                self.locations[ip_address] = location
            if location:
                geocoded_hops.append({
                    'hop_num': hop['hop_num'],
                    'hostname': hop['hostname'],
                    'ip_address': hop['ip_address'],
                    'rtt': hop['rtt'],
                    'latitude': location['latitude'],
                    'longitude': location['longitude'],
                })
        return geocoded_hops

    def get_location(self, ip_address):
        """
        Returns geolocation information for the given IP address.
        """
        location = None
        url = "http://dazzlepod.com/ip/{}.json".format(ip_address)
        status_code, json_data = self.urlopen(url)
        if status_code == 200 and json_data:
            tmp_location = json.loads(json_data)
            if 'latitude' in tmp_location and 'longitude' in tmp_location:
                location = tmp_location
        return location
