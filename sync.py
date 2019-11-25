#!/bin/sh
"exec" "`dirname $0`/.env/bin/python" "$0" "$@"

import argparse
import configparser
import logging
import sys

import requests
from CloudFlare import CloudFlare

logging.basicConfig(format="[%(levelname)5s] %(message)s", level=logging.INFO)

CONFIG_FILE = "config.ini"

CONFIG_SECTIONS = ['cloudflare']

def main(argv):
    args = parse_args(argv)

    global config
    config = configparser.ConfigParser()
    config.read_file(open(args.config))

    global cf
    cf = CloudFlare(
        email=config['cloudflare']['CF_API_EMAIL'],
        token=config['cloudflare']['CF_API_KEY'])

    zone_id = get_zone_id()

    sections = [s for s in config.sections() if s not in CONFIG_SECTIONS]

    dns_records = build_records(sections)

    for dns_record in dns_records:
        old_records = get_existing_records(dns_record, zone_id)
        r = update_record(dns_record, old_records=old_records, zone_id=zone_id, noop=args.noop)
        if r: logging.info("Update result: %s", r)

def parse_args(argv):
    options = argparse.ArgumentParser()
    options.add_argument("--verbose", '-v', default=False, action='store_true')
    options.add_argument("--config", '-c', default=CONFIG_FILE)
    options.add_argument("--noop", "-n", default=False, action='store_true')
    args = options.parse_args(argv[1:])
    if args.verbose:
        logging.getLogger('').setLevel(logging.DEBUG)
    return args


def get_existing_records(dns_record, zone_id):
    params = {'name': dns_record['name'], 'match': 'all', 'type': dns_record['type']}
    old_records = cf.zones.dns_records.get(zone_id, params=params)
    logging.info(f"Existing records for {dns_record['name']} ({dns_record['type']}): %s", old_records)
    return old_records


def update_record(dns_record, old_records, zone_id, noop=False):
    if old_records:
        old_record = next(iter(old_records))
        if all([old_record[p] == dns_record[p] for p in ['name', 'type', 'content']]):
            logging.info("Skipping up-to-date record.")
            return
        if noop:
            return f"Would update {old_record['id']} to {dns_record}"
        return cf.zones.dns_records.put(zone_id, old_record['id'], data=dns_record)
    else:
        if noop:
            return f"Would add new record {dns_record}"
        return cf.zones.dns_records.post(zone_id, data=dns_record)


def get_zone_id():
    zone = config['cloudflare']['zone']
    zone_info = cf.zones.get(params={'name': zone})
    logging.debug("Zone info: %s", zone_info)
    zone_id = zone_info[0]['id']
    return zone_id


def build_records(sections):
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
    if section.get('ip_endpoint'):
        return requests.get(section['ip_endpoint']).text
    elif section.get('value'):
        return section['value']
    else:
        logging.error('Neither "ip_endpoint" nor "value" specified for %s', section)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
