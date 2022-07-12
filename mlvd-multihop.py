#!/usr/bin/python
#   
#   Copyright 2021 Jonathan Davies
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

import argparse
import json
import os

def parse_mullvad_json(payload, ip_family):
    target_dict = {}

    for country in payload['countries']:
        for city in country['cities']:
            city_code = city['code']

            for relay in city['relays']:
                relay_name = "%s-%s" % (
                        relay['hostname'].rstrip('-wireguard'),
                        city_code)

                # Handle potential missing IP address case?
                if (ip_family == 4 and 'ipv4_addr_in' not in relay) or \
                    (ip_family == 6 and 'ipv6_addr_in' not in relay):
                    print("Skipping relay %s: does not have an IP%s address" %
                            (relay_name, ip_family))
                    continue

                target_dict[relay_name] = { 'multihop_port': relay['multihop_port'],
                                            'public_key': relay['public_key'] }

                if ip_family == 4:
                    target_dict[relay_name]['ip'] = relay['ipv4_addr_in']
                if ip_family == 6:
                    target_dict[relay_name]['ip'] = relay['ipv6_addr_in']

    return target_dict

def generate_permutations(target, endpoints, options):
    target_port = endpoints.get(target)['multihop_port']
    target_pubkey = endpoints.get(target)['public_key']

    for endpoint, endpoint_values in endpoints.items():
        if options.filter_by == "city" and target[-3:] == endpoint[-3:]:
            # Filter out endpoints in same city
            #print("Skipping %s -> %s is in same city (%s)" % (endpoint,
            #                                                  target,
            #                                                  target[-3:]))
            continue
        if options.filter_by == "country" and target[:2] == endpoint[:2]:
            # Filter out endpoints in same country
            #print("Skipping %s -> %s is in same county (%s)" % (endpoint,
            #                                                    target,
            #                                                    target[:2]))
            continue

        multihop_target_name = "%s%s" % (endpoint[:endpoint.index('-')],
                                         target[:target.index('-')])
        final_config_path = "%s/mlvd-%s.conf" % (options.config_dir,
                                                 multihop_target_name)

        if options.ip_family == 6:
            final_config_path = final_config_path.replace("mlvd", "mlvd6")

        f = open(final_config_path, 'w')
        f.write("[Interface]\n")
        f.write("PrivateKey = %s\n" % options.wg_key)
        f.write("Address = %s\n" % options.wg_address)
        f.write("DNS = 193.138.218.74\n")
        if options.wg_mtu:
            f.write("MTU = %d\n" % options.wg_mtu)
        f.write("\n")
        f.write("[Peer]\n")
        f.write("PublicKey = %s\n" % target_pubkey)
        f.write("AllowedIPs = 0.0.0.0/0,::0/0\n")
        if options.ip_family == 4:
            f.write("Endpoint = %s:%s\n" % (endpoint_values['ip'], target_port))
        if options.ip_family == 6:
            f.write("Endpoint = [%s]:%s\n" % (endpoint_values['ip'], target_port))
        f.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="Generate Mullvad multihop configurations.")
    parser.add_argument('--config-dir',
            help="Directory to write WireGuard configurations to",
            required=True)
    parser.add_argument('--filter-by',
            choices=['city', 'country'],
            default="country",
            help="Whether to filter multihop options by city or country")
    parser.add_argument('--ip-family',
            choices=[4, 6],
            default=4,
            help="IP family to generate configurations for",
            type=int)
    parser.add_argument('--json', help="Mullvad endpoint JSON file",
            required=True)
    parser.add_argument('--wg-mtu',
            help="MTU to use for WireGuard interface",
            type=int)
    parser.add_argument('--wg-key',
            help="User's Mullvad private key", required=True)
    parser.add_argument('--wg-address',
            help="User's Mullvad client address", required=True)
    
    args = parser.parse_args()

    if not os.path.isfile(args.json):
        parser.error("Mullvad JSON file not found at: %s" % args.json)

    if not os.path.isdir(args.config_dir):
        parser.error("Target configuration directory does not exist at: %s" % args.config_dir)

    if len(args.wg_key) != 44:
        parser.error("Specified WireGuard key is not valid.")

    if args.wg_mtu <= 1279 or args.wg_mtu >= 8921:
        parser.error("MTU must be between 1280 and 8920, not: %d" % args.wg_mtu)

    f = open(args.json, 'r').read()
    f_json = json.loads(f)

    mullvad_endpoints = parse_mullvad_json(f_json, args.ip_family)

    for i in mullvad_endpoints:
        generate_permutations(i, mullvad_endpoints, args)
