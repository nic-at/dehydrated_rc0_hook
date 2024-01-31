#!/usr/bin/python3

import sys
import requests
import json
import os
import yaml
import argparse
import logging
import logging.handlers
import time
from pathlib import Path
from pprint import PrettyPrinter

# Preparations
api="https://my.rcodezero.at/api/v1/acme"
ttl = 600
pp=PrettyPrinter(indent=4)
script_path=Path(__file__)
DEBUG=False

# Logging Stuff
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Set Console Logger
console_handler = logging.StreamHandler()
console_handler.setFormatter( logging.Formatter('rc0-HOOK (%(levelname)8s): %(asctime)s: %(message)s', '%Y-%m-%dT%H:%M:%S%z')  )
console_handler.setLevel(logging.INFO)
logger.addHandler( console_handler)

# If Required more debug log to file - can be changed a few lines up with DEBUG=False/True
if DEBUG:
    log_file=Path(script_path.resolve().parents[0] / 'rc0_hook_debug.log')
    should be copied from the sample file and filled with the correct data.
    log_file_handler = logging.handlers.RotatingFileHandler(filename=log_file, backupCount=10, maxBytes=100000000)
    log_file_handler.setLevel(logging.DEBUG)
    log_file_handler.setFormatter( logging.Formatter('%(name)s: { "timestamp_logged": "%(asctime)s", "log.level" : "%(levelname)s", "program": "%(name)s", "log.origin.function": "%(funcName)s", "log.origin.file.line" : "%(lineno)d",  %(message)s }', '%Y-%m-%dT%H:%M:%S%z')  )
    logger.addHandler(log_file_handler)

try:
    fp=os.environ['RCODE0_CONFIG_FILE']
    conf_path=Path(fp)
except:
    logger.debug("Environment Variable misses RCODE0_CONFIG_FILE for config file location - fall back to default")
    conf_path=Path(script_path.resolve().parents[0] / 'rc0_conf.yaml')

if conf_path.exists():
    conf=yaml.safe_load(conf_path.read_text())
else:
    logger.error(f"Config File missing or Location wrong: {conf_path}")
    sys.exit(1)

def parsing():
    parser = argparse.ArgumentParser(description="rc0_dehydrated_hook.py" +
                                                 " Lets get some certificates")
    parser.add_argument('hooktype', help="What should we do?", nargs="?")
    parser.add_argument('domain', help="The Domainname", nargs="?")

    (sys_args, unknown)=parser.parse_known_args()

    logger.debug(f'Script called with sys_args: {sys_args} and unknown: {unknown}')

    #if sys_args.hooktype in [ 'deploy_challenge', 'invalid_challenge', 'clean_challenge']:
    if sys_args.hooktype in [ 'deploy_challenge', 'clean_challenge' ]:
        pass
    elif sys_args.hooktype in [ 'startup_hook', 'invalid_challenge' ]:
        sys.exit(0)
    else:
        sys.exit(0)

    args={
            'hooktype'  : sys_args.hooktype,
            'domain'    : sys_args.domain,
            'token'     : unknown[0],
            'challenge' : unknown[1],
            }

    return(args)

def get_api_and_superdomain(args):
    # Check if we have a api key for the domain in the config file
    # else we use default
    
    domain=args['domain']
    domain_length=len(domain.split("."))

    counter=0
    found=False
    while counter < domain_length:
        # We check everything if a specific domain (wildcard) is required
        superdomain=".".join(domain.split(".")[counter:])
        counter+=1
        if superdomain in conf.keys():
            found=True
            break
    
    logger.debug(f'Superdomain FOUND: {superdomain} for domain: {domain} in {conf.keys()}')
    if found:
        api_slot=superdomain
    else:
        api_slot='default'

    api_key=conf[api_slot]['Bearer']

    headers = { "Content-Type": "application/json", "Authorization": "Bearer " + api_key }
    # Next we search for the correct zone in rc0 - as there may be more specific
    # subdomains there - we search until we hit a 200er RC
    counter=0
    found=False
    while counter < domain_length:
        superdomain=".".join(domain.split(".")[counter:])
        counter+=1
        data = requests.get(url=api + f"/zones/{superdomain}", headers=headers )
        if data.status_code == 200:
            found=True
            logger.info(f"Domain: {superdomain} found as parent zone with API-Key ({api_slot}) to work in - continuing")
            break
    
    if not found:
        logger.error(f"No Domain: {domain} in Rcode0 with API-Key for Slot ({api_slot}) found:")
        sys.exit(1)
    
    return(api_key, superdomain)

def get_txt_rrsets(api_key, superdomain, label=""):
    headers = { "Content-Type": "application/json", "Authorization": "Bearer " + api_key }
    page=1
    max_page=1
    result=[]

    while True:
        data = requests.get(url=f"{api}/zones/{superdomain}/rrsets", headers=headers, 
                            params={'types'    : 'TXT',
                                    'names'    : label,
                                    'page'     : page, 
                                    'page_size': 50
                                    })
        max_page=data.json()['last_page']
        result+=data.json()['data']
        page+=1

        if page >= max_page:
            break

    return(result)

def deploy_challenge(args, api_key, superdomain):
    domain = args['domain']
    challenge = args['challenge']
    headers = { "Content-Type": "application/json", "Authorization": "Bearer " + api_key }
    label=f'_acme-challenge.{domain}'
    # Query Label for GET is different
    querylabel=label.replace(f".{superdomain}", "")

    logger.debug(f"Searching ({querylabel}) in Superdomain ({superdomain}")

    records=[{ 'content' : challenge }]

    # Check if Entry exists to know if we should patch or add
    rrset=get_txt_rrsets(api_key, superdomain, querylabel)
    if len(rrset) == 0:
        changetype='add'
        logger.debug(f"No exiting TXT record - continuing with add")
    elif len(rrset) == 1:
        logger.debug(f"Existing TXT record found for {label} in {superdomain} - I'm Doing a Patch instead of an add!")
        changetype='update'
        records+=rrset[0]['records']
    else:
        logger.error(f"More than one result for search returned for {label} in {superdomain} - I'm exiting now")

    
    logger.debug(f"Deploying ({label}.) in Superdomain ({superdomain}")
    # Patch new _acme-challenge to contain wanted challenge
    patch=[{
        'name'      : f'{label}.',
        'type'      : 'TXT',
        'ttl'       : ttl,
        'changetype': changetype,
        'records'   : records,
    }]
    data = requests.patch(url=f"{api}/zones/{superdomain}/rrsets", headers=headers, data=json.dumps(patch))
    if data.status_code != 200:
        logger.error(f"Adding TXT Record {label} to SuperDomain: {superdomain} failed because: {data.json()} : Records: {records} - rrset: {rrset}")
        sys.exit(1)

    logger.info(f"Adding TXT Record {label} to SuperDomain: {superdomain} was successful - waiting 30 Seconds before continue!")

    # Wait 30 seconds for propgatation
    time.sleep(30)

    return None


def clean_challenge(args, api_key, superdomain):
    domain = args['domain']
    challenge = args['challenge']
    headers = { "Content-Type": "application/json", "Authorization": "Bearer " + api_key }
    label=f'_acme-challenge.{domain}'
    # Query Label for GET is different
    querylabel=label.replace(f".{superdomain}", "")

    logger.debug(f"Searching ({querylabel}) in Superdomain ({superdomain}")
    rrset=get_txt_rrsets(api_key, superdomain, querylabel)
    if len(rrset) == 0:
        logger.info(f"No TXT record found for Cleaning of {label} in {superdomain} - Happens in case of Wildcards, because the first delete cleans all _acme-challenges")

    else:
        logger.debug(f"Cleaning ({label}.) in Superdomain ({superdomain}")
        # Patch new _acme-challenge to contain wanted challenge
        patch=[{
            'name'      : f'{label}.',
            'type'      : 'TXT',
            'ttl'       : ttl,
            'changetype': 'delete'
        }]
        data = requests.patch(url=f"{api}/zones/{superdomain}/rrsets", headers=headers, data=json.dumps(patch))
        if data.status_code != 200:
            logger.error(f"Cleaning of TXT Record {label} in Superdomain: {superdomain} failed because: {data.json()}")
            sys.exit(1)
    
    logger.info(f"Cleaning TXT Record from Domain {label}: in Superdomain: {superdomain} was successful!")


def main():
    (args)=parsing()

    if args['hooktype'] in [ "deploy_challenge", "clean_challenge" ]:
        (api_key, superdomain)=get_api_and_superdomain(args)

    if args['hooktype'] == "deploy_challenge":    
        deploy_challenge(args, api_key, superdomain)

    elif args['hooktype'] == "clean_challenge":
        clean_challenge(args, api_key, superdomain)
    
    elif args['hooktype'] == "deploy_cert":
        sys.exit(0)

    else:
        sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    main()
