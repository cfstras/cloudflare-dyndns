#!/bin/sh
"exec" "`dirname $0`/.env/bin/python" "$0" "$@"

import argparse
import configparser
import logging
import sys
import urllib

import CloudFlare
import requests
from CloudFlare import CloudFlare

logging.basicConfig(format="[%(levelname)5s] %(message)s", level=logging.INFO)

CONFIG_FILE = "config.ini"

CONFIG_SECTIONS = ['cloudflare']

def main(argv):
    args = parse_args(argv)

    config = configparser.ConfigParser()
    config.read_file(open(args.config))

    cf = CloudFlare.CloudFlare(
        email=config['cloudflare']['CF_API_EMAIL'],
        token=config['cloudflare']['CF_API_KEY'])

    zone_id = get_zone_id(cf, config)

    sections = [s for s in config.sections() if s not in CONFIG_SECTIONS]

    dns_records = build_records(config, sections)

    for dns_record in dns_records:
        params = {'name': dns_record['name'], 'match': 'all', 'type': dns_record['type']}
        old_records = cf.zones.dns_records.get(zone_id, params=params)
        logging.info(f"Existing records for {dns_record['name']} ({dns_record['type']}): %s", old_records)
        if old_records:
            record = next(iter(old_records))
            r = cf.zones.dns_records.put(zone_id, record['id'], data=dns_record)
        else:
            r = cf.zones.dns_records.post(zone_id, data=dns_record)
        logging.info("Update result:%s", r)


def get_zone_id(cf, config):
    zone = config['cloudflare']['zone']
    zone_info = cf.zones.get(params={'name': zone})
    logging.debug("Zone info: %s", zone_info)
    zone_id = zone_info[0]['id']
    return zone_id


def parse_args(argv):
    options = argparse.ArgumentParser()
    options.add_argument("--verbose", '-v', default=False, action='store_true')
    options.add_argument("config", default=CONFIG_FILE)
    args = options.parse_args(argv[1:])
    if args.verbose:
        logging.getLogger('').setLevel(logging.DEBUG)
    return args


def build_records(config, sections):
    for section_name in sections:
        section = config[section_name]
        hostname = section['hostname']
        if hostname:
            ip = query_external_ip(section)
            record = {
                'name': hostname,
                'type': section['type'],
                'content': ip.strip(),
                'ttl': int(section.get('ttl', 1))  # 1 is default
            }
            logging.info("Queried IP: %s", record)
            yield record


def query_external_ip(section):
    ip = requests.get(section['ip_endpoint']).text
    return ip


if __name__ == "__main__":
    sys.exit(main(sys.argv))
