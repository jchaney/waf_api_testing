#!/usr/bin/env python3

import sys, requests, configparser, json
import boto3
from rich import print
from rich.panel import Panel
from rich.console import Console
from rich.table import Table
from requests.auth import AuthBase


# GLOBALS
CREDS_FILE = 'api_creds.env'
CF_BASE_URL = 'https://api.cloudflare.com/client/v4'


class Zone():
    def __init__(self, zone):
        self.id = zone['id']
        self.name = zone['name']
        self.status = zone['status']
        self.development_mode = zone['development_mode']
        self.rulesets = []


def main():
    # GET API TOKENS FROM ENV FILE
    creds = configparser.ConfigParser()
    creds.read(CREDS_FILE)
    try:
        cf_token = creds['cloudflare']['CF_API_TOKEN']
    except:
        sys.exit(f"*** Unable to read CF_API_TOKEN from {CREDS_FILE}")
    try:
        aws_access_key_id, aws_secret_access_key = creds['aws']['AWS_ACCESS_KEY_ID'], creds['aws']['AWS_SECRET_ACCESS_KEY']
    except:
        sys.exit(f"*** Unable to read AWS API CREDS from {CREDS_FILE}")

    # Cloudflare Stuff
    print(Panel.fit("Cloudflare WAF Protection Status"))
    cf_s = requests.Session() # Create Session
    cf_s.headers.update({'Authorization': f'Bearer {cf_token}'}) # Add bearer token to all session requests
    zones = cf_s.get(f'{CF_BASE_URL}/zones').json()['result'] # GET zones
    for zone in zones:
        z = Zone(zone)
        rulesets = cf_s.get(f'{CF_BASE_URL}/zones/{z.id}/rulesets').json()['result'] # GET rulesets
        for ruleset in rulesets:
            z.rulesets.append({
                'id': ruleset['id'],
                'name': ruleset['name'],
                'description': ruleset['description'],
                'phase': ruleset['phase']
            })

        # Make a pretty table with the data
        table = Table(title=z.name)
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Status", style="bright_green") if z.status == 'active' else table.add_column("Status", style="bright_red")
        table.add_column("Development Mode")
        table.add_column("Rule Sets")
        short_list = [x['name'] for x in z.rulesets]
        table.add_row(z.id, z.name, z.status, str(z.development_mode), '\n'.join(short_list))
        console = Console()
        console.print(table)


    # AWS Stuff
    print(Panel.fit("AWS WAF Protection Status"))
    aws_client = boto3.client(
        'wafv2',
        region_name = 'us-east-1',
        aws_access_key_id = aws_access_key_id,
        aws_secret_access_key = aws_secret_access_key
    )
    acls = aws_client.list_web_acls(
        Scope='CLOUDFRONT',
        NextMarker='string',
        Limit=100
    )
    rule_groups = aws_client.list_rule_groups(
        Scope='CLOUDFRONT',
        NextMarker='string',
        Limit=100
    )
    #print(acls) # THIS IS BROKE. Returning empty list.



if __name__ == '__main__':
    main()
