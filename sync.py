#!/bin/sh
"exec" "`dirname $0`/.env/bin/python" "$0" "$@"

import argparse
import configparser
import logging
import sys
import urllib

import CloudFlare
import requests

logging.basicConfig(format="[%(levelname)5s] %(message)s", level=logging.INFO)

CONFIG = "config.ini"

CONFIG_SECTIONS = ['cloudflare']

def main(argv):
    options = argparse.ArgumentParser()
    options.add_argument("--verbose", '-v', default=False, action='store_true')
    args = options.parse_args(argv[1:])
    if args.verbose:
        logging.getLogger('').setLevel(logging.DEBUG)

    config = configparser.ConfigParser()
    config.read_file(open(CONFIG))

    cf = CloudFlare.CloudFlare(
        email=config['cloudflare']['CF_API_EMAIL'],
        token=config['cloudflare']['CF_API_KEY'])

    zone = config['cloudflare']['zone']
    zone_info = cf.zones.get(params={'name': zone})
    zone_id = zone_info[0]['id']

    sections = [s for s in config.sections() if s not in CONFIG_SECTIONS]

    dns_records = []
    for section_name in sections:
        section = config[section_name]
        hostname = section['hostname']
        if hostname:
            ip = requests.get(section['ip_endpoint']).text
            record = {
                'name': hostname,
                'type': section['type'],
                'content': ip.strip(),
                'ttl': int(section.get('ttl', 1)) # 1 is default
            }
            dns_records.append(record)
            logging.info("Queried IP: %s", record)

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

if __name__ == "__main__":
    sys.exit(main(sys.argv))
