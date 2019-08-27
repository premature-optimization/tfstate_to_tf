import json
import os
import subprocess
import jinja2
import logging as log
import re
import sys

state_path = input("What is the full path to the statefile you want to convert? \n")
type(state_path)
state_name = state_path.split('/')[-1]
vpc_outfile = "vpcs.tf"
py_version = sys.version.split(' ')[0]
py2_regex = re.compile("^2.*", re.MULTILINE)
py3_regex = re.compile("^3.*", re.MULTILINE)

#JINJA has separate parameter names based on version of Python
#This checks Python version and directs to the correct template
if py2_regex.match(py_version):
    with open('templates_py2/security-group.template') as f:
        sg_template = jinja2.Template(f.read())
    with open('templates_py2/security-group-rule.template') as f:
        sg_rule_template = jinja2.Template(f.read())
    with open('templates_py2/route53-record.template') as f:
        r53_record_template = jinja2.Template(f.read())
    with open('templates_py2/route53-zone.template') as f:
        r53_zone_template = jinja2.Template(f.read())
    with open('templates_py2/vpc.template') as f:
        vpc_template = jinja2.Template(f.read())
    with open('templates_py2/subnet.template') as f:
        subnet_template = jinja2.Template(f.read())
    with open('templates_py2/vpc-dhcp-options.template') as f:
        vpc_dhcp_options_template = jinja2.Template(f.read())
    with open('templates_py2/vpc-dhcp-options-association.template') as f:
        vpc_dhcp_options_association_template = jinja2.Template(f.read())
    with open('templates_py2/vpc-endpoint.template') as f:
        vpc_endpoint_template = jinja2.Template(f.read())
    with open('templates_py2/vpn-gateway.template') as f:
        vpn_gateway_template = jinja2.Template(f.read())
    with open('templates_py2/eip.template') as f:
        eip_template = jinja2.Template(f.read())
    with open('templates_py2/nat-gateway.template') as f:
        nat_gateway_template = jinja2.Template(f.read())
    with open('templates_py2/route.template') as f:
        route_template = jinja2.Template(f.read())
    with open('templates_py2/route-table.template') as f:
        route_table_template = jinja2.Template(f.read())
    with open('templates_py2/route-table-association.template') as f:
        route_table_association_template = jinja2.Template(f.read())
elif py3_regex.match(py_version):
    with open('templates_py3/security-group.template') as f:
        sg_template = jinja2.Template(f.read())
    with open('templates_py3/security-group-rule.template') as f:
        sg_rule_template = jinja2.Template(f.read())
    with open('templates_py3/route53-record.template') as f:
        r53_record_template = jinja2.Template(f.read())
    with open('templates_py3/route53-zone.template') as f:
        r53_zone_template = jinja2.Template(f.read())
    with open('templates_py3/vpc.template') as f:
        vpc_template = jinja2.Template(f.read())
    with open('templates_py3/subnet.template') as f:
        subnet_template = jinja2.Template(f.read())
    with open('templates_py3/vpc-dhcp-options.template') as f:
        vpc_dhcp_options_template = jinja2.Template(f.read())
    with open('templates_py3/vpc-dhcp-options-association.template') as f:
        vpc_dhcp_options_association_template = jinja2.Template(f.read())
    with open('templates_py3/vpc-endpoint.template') as f:
        vpc_endpoint_template = jinja2.Template(f.read())
    with open('templates_py3/vpn-gateway.template') as f:
        vpn_gateway_template = jinja2.Template(f.read())
    with open('templates_py3/eip.template') as f:
        eip_template = jinja2.Template(f.read())
    with open('templates_py3/nat-gateway.template') as f:
        nat_gateway_template = jinja2.Template(f.read())
    with open('templates_py3/route.template') as f:
        route_template = jinja2.Template(f.read())
    with open('templates_py3/route-table.template') as f:
        route_table_template = jinja2.Template(f.read())
    with open('templates_py3/route-table-association.template') as f:
        route_table_association_template = jinja2.Template(f.read())

log.basicConfig(
     level=log.INFO,
     format="[%(asctime)s]:%(levelname)s: %(message)s",
     datefmt="%H:%M:%S"
 )

# RegEx filters used in multiple places
tag_regex = re.compile("tags\.(?!\%)")
route_table_regex = re.compile("route_table_ids\.(?!\#)")
subnet_regex = re.compile("subnet_ids\.(?!\#)")
security_group_regex = re.compile("security_group_ids\.(?!\#)")
vpc_regex = re.compile("vpc\.(?!\#)")
nameserver_regex = re.compile("name_servers\.(?!\#)")

# Dictionaries to be available globally
# Used to tie subnets to VPC names
used_vpcs = {}
# Used to ensure unique resource names for EIPs
used_eips = []
# Used to ensure unique resource names
used_resource_names = {}

# Reads through a tfstate file and branches out to other functions
def state_parser(state_path):
    outputs = {}
    resources = []
    with open(state_path, 'r') as state:
        state_json = json.loads(state.read())
        state_version = state_json["version"]
        if state_version == 3:
            log.info('Statefile version 3 - TF version >= 0.11.1')
            all_modules = state_json["modules"]
            for module in all_modules:
                if module["outputs"]:
                    output_dict = module["outputs"]
                    for key, value in output_dict.items():
                        output_item_name = key
                        output_item_values = output_dict[key]
                        print("The converter currently does not support outputs")
                if module["resources"]:
                    resource_dict = module["resources"]
                    # passes the resource block to another function
                    for resource_name, resource_value in resource_dict.items():
                        # adds resource name to list of found resources
                        resources.append(resource_name)
                        resource_type = resource_value["type"]
                        resource_attributes = resource_value["primary"]["attributes"]
                        resource_handler(resource_name, resource_attributes, resource_type)
        elif state_version == 4:
            log.info('Statefile version 4 - TF version >= 0.12.1')
            resources = state_json["resources"]
            for resource in resources:
                resource_type = resource["type"]
                if resource["mode"] == "managed":
                    try:
                        resource_each = resource["each"]
                        if resource_each == "list":
                            all_instances = resource["instances"]
                            for instance in all_instances:
                                instance_count = instance["index_key"]
                                instance_attributes = instance["attributes_flat"]
                                resource_name = "{}.{}.{}".format(resource_type, resource["name"], instance_count)
                                resource_handler(resource_name, instance_attributes, resource_type)
                    except KeyError:
                        resource_attributes = resource["instances"][0]["attributes_flat"]
                        resource_name = "{}.{}".format(resource_type, resource["name"])
                        resource_handler(resource_name, resource_attributes, resource_type)



# decides which function to write Terraform for statefiles
def resource_handler(resource_name, resource_attributes, resource_type):
    #resource_dependencies = resource_value["depends_on"]
    if resource_type == "aws_security_group" and "data." not in resource_name:
        security_group(resource_name, resource_attributes)
    elif resource_type == "aws_route53_record" and "data." not in resource_name:
        route53_record(resource_name, resource_value)
    elif resource_type == "aws_route53_zone" and "data." not in resource_name:
        route53_zone(resource_name, resource_attributes)
    elif resource_type == "aws_vpc" and "data." not in resource_name:
        vpc(resource_name, resource_attributes)
    elif resource_type == "aws_subnet" and "data." not in resource_name:
        subnet(resource_name, resource_attributes)
    elif resource_type == "aws_vpc_dhcp_options" and "data." not in resource_name:
        vpc_dhcp_options(resource_name, resource_attributes)
    elif resource_type == "aws_vpc_dhcp_options_association" and "data." not in resource_name:
        vpc_dhcp_options_association(resource_name, resource_attributes)
    elif resource_type == "aws_vpc_endpoint" and "data." not in resource_name:
        vpc_endpoint(resource_name, resource_attributes)
    elif resource_type == "aws_vpn_gateway" and "data." not in resource_name:
        vpn_gateway(resource_name, resource_attributes)
    elif resource_type == "aws_eip" and "data." not in resource_name:
        eip(resource_name, resource_attributes)
    elif resource_type == "aws_nat_gateway" and "data." not in resource_name:
        nat_gateway(resource_name, resource_attributes)
    elif resource_type == "aws_route" and "data." not in resource_name:
        route(resource_name, resource_attributes)
    elif resource_type == "aws_route_table" and "data." not in resource_name:
        route_table(resource_name, resource_attributes)
    elif resource_type == "aws_route_table_association" and "data." not in resource_name:
        route_table_association(resource_name, resource_attributes)


# Writes security group HCL to security_groups file
def security_group(name, values):
    sg_outfile = "security_groups.tf"
    arn_values = arn_parser(values["arn"])
    region = arn_values[0]
    acct_id = arn_values[1]
    sg_name = values["name"]
    sg_description = values["description"]
    sg_tags = {}
    sg_vpc_id = values["vpc_id"]
    sg_owner_id = values["owner_id"]
    sg_all_rules_dict = {}
    sg_rule_regex = re.compile("(ingress|egress)(?!.*\#)")
    sg_cidr_regex = re.compile("cidr_blocks")
    sg_port_regex = re.compile("")
    for k, v in values.items():
        if sg_rule_regex.match(k):
            sg_rule_split = k.split('.')
            sg_rule_type = sg_rule_split[0]
            if not sg_rule_split[1] == '#':
                sg_rule_id = sg_rule_split[1]
                sg_rule_param = sg_rule_split[2]
                sg_rule_set = {sg_rule_param: v}
                sg_rule_dict = {sg_rule_id: {sg_rule_type: sg_rule_set}}
                if sg_cidr_regex.match(sg_rule_param):
                    if sg_rule_type == "egress" or sg_rule_type == "ingress":
                        if sg_cidr_regex.match(sg_rule_param):
                            sg_cidr_rule_set = {sg_rule_param: [v]}
                            sg_cidr_rule_dict = {sg_rule_id: {sg_rule_type: sg_cidr_rule_set}}
                            try:
                                if v not in sg_all_rules_dict[sg_rule_id][sg_rule_type][sg_rule_param]:
                                    sg_all_rules_dict[sg_rule_id][sg_rule_type][sg_rule_param].append(v)
                            except:
                                try:
                                    sg_all_rules_dict[sg_rule_id][sg_rule_type].update(sg_cidr_rule_set)
                                    if v not in sg_all_rules_dict[sg_rule_id][sg_rule_type][sg_rule_param]:
                                        sg_all_rules_dict[sg_rule_id][sg_rule_type][sg_rule_param].append(v)
                                except:
                                    sg_all_rules_dict.update(sg_cidr_rule_dict)
                elif sg_port_regex.match(sg_rule_param):
                    try:
                        if v not in sg_all_rules_dict[sg_rule_id][sg_rule_type][sg_rule_param]:
                            sg_all_rules_dict[sg_rule_id][sg_rule_type][sg_rule_param].update(v)
                    except:
                        try:
                            sg_all_rules_dict[sg_rule_id][sg_rule_type].update(sg_rule_set)
                            if v not in sg_all_rules_dict[sg_rule_id][sg_rule_type][sg_rule_param]:
                                sg_all_rules_dict[sg_rule_id][sg_rule_type][sg_rule_param].update(v)
                        except:
                            sg_all_rules_dict.update(sg_rule_dict)
        if tag_regex.match(k):
            sg_tag_dict = tags_builder(k, v)
            sg_tags.update(sg_tag_dict)

    with open(sg_outfile, "a+") as output:
        output.write(sg_template.render(
        sg_name=sg_name,
        sg_description=sg_description,
        sg_vpc_id=sg_vpc_id,
        sg_tags=sg_tags,
        sg_owner_id=sg_owner_id
        )
        )

    security_group_rule(sg_all_rules_dict, sg_name, sg_outfile)
    log.info('Added {} to security groups'.format(name))


def security_group_rule(sg_all_rules_dict, sg_name, sg_outfile):
    for sg_rule_name, sg_rule_values in sg_all_rules_dict.items():
        for sg_rule_type, sg_param_values in sg_rule_values.items():
            sg_rule_from_port = json.dumps(sg_param_values['from_port'])
            sg_rule_to_port = json.dumps(sg_param_values['to_port'])
            sg_rule_self = json.dumps(sg_param_values['self'])
            sg_rule_protocol = json.dumps(sg_param_values['protocol'])
            try:
                sg_rule_cidrs = json.dumps(sg_param_values['cidr_blocks'])
            except KeyError:
                log.info('No cidr blocks for {}'.format(sg_rule_name))
            with open(sg_outfile, "a+") as output:
                output.write(sg_rule_template.render(
                sg_name=sg_name,
                sg_rule_name=sg_rule_name,
                sg_rule_type=sg_rule_type,
                sg_rule_from_port=sg_rule_from_port,
                sg_rule_to_port=sg_rule_to_port,
                sg_rule_protocol=sg_rule_protocol,
                sg_rule_cidrs=sg_rule_cidrs,
                sg_rule_self=sg_rule_self
                )
                )
            # TO BE ADDED LATER
            # sg_rule_prefix_list_ids = sg_param_values['prefix_list_ids']
            # sg_rule_description = sg_param_values['description']
            # sg_rule_ipv6_cidr = sg_param_values['ipv6_cidr_blocks']


def route53_record(name, values):
    r53_records_outfile = "route53_records.tf"
    record_depends = values["depends_on"][0].split('.')
    record_parent_zone = record_depends[1]
    record_attributes = values["primary"]["attributes"]
    record_value_regex = re.compile("(records)(?!.*\#)")
    record_alias_regex = re.compile("(alias)(?!.*\#)")
    record_values = []
    alias_dict = {}
    record_name = record_attributes["name"]
    record_type = record_attributes["type"]
    try:
        record_ttl = record_attributes["ttl"]
    except KeyError:
        record_ttl = "300"
        print("No TTL configured for {}, defaulting to 5mins".format(record_name))
    for k, v in record_attributes.items():
        if record_value_regex.match(k):
            record_values.append(v)
        if record_alias_regex.match(k):
            alias_split = k.split('.')
            alias_param = alias_split[2]
            param_dict = {alias_param: v}
            alias_dict.update(param_dict)
    with open(r53_records_outfile, "a+") as output:
        output.write(r53_record_template.render(
        record_parent_zone=record_parent_zone,
        record_name=record_name,
        record_type=record_type,
        record_ttl=record_ttl,
        record_values=json.dumps(record_values),
        alias_dict=alias_dict
        )
        )
    log.info('Added {} to Route53 records'.format(record_name))


def route53_zone(name, values):
    r53_zones_outfile = "route53_zones.tf"
    zone_comment = values["comment"]
    zone_force_destroy = values["force_destroy"]
    zone_name = values["name"]
    zone_resource_name = name.split('.')[1]
    try:
        zone_delegation_set_id = values["delegation_set_id"]
    except:
        zone_delegation_set_id = ""
        log.info('No delegation set ID specified for {} zone'.format(zone_name))
    zone_tags = {}
    zone_name_servers = []
    zone_vpcs = {}
    for k, v in values.items():
        if tag_regex.match(k):
            zone_tag_dict = tags_builder(k, v)
            zone_tags.update(zone_tag_dict)
        elif vpc_regex.match(k):
            vpc_split = k.split('.')
            vpc_param = vpc_split[2]
            vpc_dict = {vpc_param: v}
            zone_vpcs.update(vpc_dict)
        elif nameserver_regex.match(k):
            zone_name_servers.append(str(v))
    with open(r53_zones_outfile, "a+") as output:
        output.write(r53_zone_template.render(
        zone_name=zone_name,
        zone_resource_name=zone_resource_name,
        zone_comment=zone_comment,
        zone_force_destroy=zone_force_destroy,
        zone_delegation_set_id=zone_delegation_set_id,
        zone_tags=zone_tags,
        zone_vpcs=zone_vpcs
        )
        )
    log.info('Added {} to Route53 zones'.format(zone_name))


def vpc(name, values):
    vpc_name = name.split('.')[1]
    vpc_cidr_block = values["cidr_block"]
    vpc_instance_tenancy = values["instance_tenancy"]
    vpc_dns_hostnames = values["enable_dns_hostnames"]
    vpc_dns_support = values["enable_dns_support"]
    vpc_tags = {}
    for k, v in values.items():
        if tag_regex.match(k):
            vpc_tag_dict = tags_builder(k, v)
            vpc_tags.update(vpc_tag_dict)
    try:
        vpc_name = vpc_tags["Name"]
    except KeyError:
        log.info('No unique name specified for VPC {}'.format(vpc_name))
    vpc_id = values["id"]
    to_used_vpc = {vpc_id: vpc_name}
    print(to_used_vpc)
    with open(vpc_outfile, "a+") as output:
        output.write(vpc_template.render(
        vpc_name=vpc_name,
        vpc_cidr_block=vpc_cidr_block,
        vpc_instance_tenancy=vpc_instance_tenancy,
        vpc_dns_hostnames=vpc_dns_hostnames,
        vpc_dns_support=vpc_dns_support,
        vpc_tags=vpc_tags
        )
        )
    log.info('Added {} vpc to VPCs'.format(vpc_name))
    used_vpcs.update(to_used_vpc)


def subnet(name, values):
    subnet_outfile = "subnets.tf"
    subnet_type = name.split('.')[1]
    subnet_parent = values["vpc_id"]
    subnet_cidr_block = values["cidr_block"]
    subnet_tags = {}
    try:
        subnet_ipv6_cidr = values["ipv6_cidr_block"]
    except KeyError:
        subnet_ipv6_cidr = ""
        log.info('No values for ipv6 cidr block for subnet {}'.format(name))
    subnet_az = values["availability_zone"]
    try:
        subnet_az_id = values["availability_zone_id"]
    except KeyError:
        subnet_az_id = ""
        log.info('No values for subnet AZ ID {}'.format(name))
    subnet_map_pub_ip = values["map_public_ip_on_launch"]
    subnet_assign_ipv6 = values["assign_ipv6_address_on_creation"]
    subnet_tags = {}
    for k, v in values.items():
        if tag_regex.match(k):
            subnet_tag_dict = tags_builder(k, v)
            subnet_tags.update(subnet_tag_dict)
    subnet_name = subnet_tags["Name"]
    try:
        if used_vpcs[subnet_parent]:
            subnet_parent_name = used_vpcs[subnet_parent]
            subnet_vpc_id = '${{aws_vpc.{}.id}}'.format(subnet_parent_name)
        elif not used_vpcs[subnet_parent]:
            subnet_vpc_id = subnet_parent
            print('**VPC PARENT NAME NOT FOUND, VPC ID IS HARD CODED FOR {}**'.format(subnet_name))
    except KeyError:
        subnet_vpc_id = subnet_parent
        print('**VPC PARENT NAME NOT FOUND, VPC ID IS HARD CODED FOR {}**'.format(subnet_name))
    with open(subnet_outfile, "a+") as output:
        output.write(subnet_template.render(
        subnet_name=subnet_name,
        subnet_vpc_id=subnet_vpc_id,
        subnet_cidr_block=subnet_cidr_block,
        subnet_az=subnet_az,
        subnet_az_id=subnet_az_id,
        subnet_map_pub_ip=subnet_map_pub_ip,
        subnet_assign_ipv6=subnet_assign_ipv6,
        subnet_ipv6_cidr=subnet_ipv6_cidr,
        subnet_tags=subnet_tags
        )
        )
    log.info('Added {} to subnets'.format(subnet_name))


def vpc_dhcp_options(name, values):
    vpc_dhcp_opts_name = name.split('.')[1]
    vpc_dhcp_opts_ns_regex = re.compile("domain_name_servers(?!.\#)")
    vpc_dhcp_opts_domain = values["domain_name"]
    vpc_dhcp_opts_dns_servers = []
    vpc_dhcp_opts_ntp_servers = []
    vpc_dhcp_opts_netbios_ns = []
    vpc_dhcp_opts_netbios_node_type = ""
    vpc_dhcp_opts_tags = {}
    vpc_dhcp_opts_id = values["id"]
    try:
        vpc_dhcp_opts_ntp_servers.append(str(values["ntp_servers"]))
    except KeyError:
        log.info('No NTP servers specified for {}'.format(vpc_dhcp_opts_name))
    try:
        vpc_dhcp_opts_netbios_ns.append(str(values["netbios_name_servers"]))
    except KeyError:
        log.info('No NetBIOS NS servers specified for {}'.format(vpc_dhcp_opts_name))
    try:
        vpc_dhcp_opts_netbios_node_type = values["netbios_node_type"]
    except KeyError:
        log.info('No NetBIOS node type specified for {}'.format(vpc_dhcp_opts_name))
    for k, v in values.items():
        if tag_regex.match(k):
            vpc_dhcp_opts_tag_dict = tags_builder(k, v)
            vpc_dhcp_opts_tags.update(vpc_dhcp_opts_tag_dict)
        elif vpc_dhcp_opts_ns_regex.match(k):
            vpc_dhcp_opts_dns_servers.append(str(v))
    with open(vpc_outfile, "a+") as output:
        output.write(vpc_dhcp_options_template.render(
        vpc_dhcp_opts_name=vpc_dhcp_opts_name,
        vpc_dhcp_opts_domain=vpc_dhcp_opts_domain,
        vpc_dhcp_opts_dns_servers=vpc_dhcp_opts_dns_servers,
        vpc_dhcp_opts_ntp_servers=vpc_dhcp_opts_ntp_servers,
        vpc_dhcp_opts_netbios_ns=vpc_dhcp_opts_netbios_ns,
        vpc_dhcp_opts_netbios_node_type=vpc_dhcp_opts_netbios_node_type,
        vpc_dhcp_opts_tags=vpc_dhcp_opts_tags
        )
        )
    log.info('Added {} to VPC DHCP Options sets'.format(vpc_dhcp_opts_name))


def vpc_dhcp_options_association(name, values):
    vpc_dhcp_opts_assoc_name = name.split('.')[1]
    vpc_dhcp_opts_assoc_dhcp_opts_id = values["dhcp_options_id"]
    vpc_dhcp_opts_assoc_vpc_id = values["vpc_id"]
    with open(vpc_outfile, "a+") as output:
        output.write(vpc_dhcp_options_association_template.render(
        vpc_dhcp_opts_assoc_name=vpc_dhcp_opts_assoc_name,
        vpc_dhcp_opts_assoc_dhcp_opts_id=vpc_dhcp_opts_assoc_dhcp_opts_id,
        vpc_dhcp_opts_assoc_vpc_id=vpc_dhcp_opts_assoc_vpc_id
        )
        )
    log.info('Added {} to VPC DHCP Options Associations'.format(vpc_dhcp_opts_assoc_name))


def vpc_endpoint(name, values):
    vpc_endpoint_name = name.split('.')[1]
    vpc_endpoint_service_name = values["service_name"]
    vpc_endpoint_vpc_id = values["vpc_id"]
    # vpc_endpoint_auto_accept = ""
    vpc_endpoint_policy = values["policy"]
    try:
        vpc_endpoint_private_dns = values["private_dns_enabled"]
    except KeyError:
        vpc_endpoint_private_dns = ""
        log.info('Enable private DNS unspecified for {} VPC endpoint'.format(vpc_endpoint_name))
    vpc_endpoint_route_table_ids = []
    vpc_endpoint_subnet_ids = []
    vpc_endpoint_security_group_ids = []
    vpc_endpoint_tags = {}
    try:
        vpc_endpoint_type = values["vpc_endpoint_type"]
    except KeyError:
        vpc_endpoint_type = ""
        log.info('No VPC endpoint type specified for {}'.format(vpc_endpoint_name))
    for k, v in values.items():
        if tag_regex.match(k):
            vpc_endpoint_tag_dict = tags_builder(k, v)
            vpc_endpoint_tags.update(vpc_endpoint_tag_dict)
        elif route_table_regex.match(k):
            vpc_endpoint_route_table_ids.append(v)
        elif subnet_regex.match(k):
            vpc_endpoint_subnet_ids.append(v)
        elif security_group_regex.match(k):
            vpc_endpoint_security_group_ids.append(v)
    with open(vpc_outfile, "a+") as output:
        output.write(vpc_endpoint_template.render(
        vpc_endpoint_name=vpc_endpoint_name,
        vpc_endpoint_service_name=vpc_endpoint_service_name,
        vpc_endpoint_vpc_id=vpc_endpoint_vpc_id,
        vpc_endpoint_policy=vpc_endpoint_policy,
        vpc_endpoint_private_dns=vpc_endpoint_private_dns,
        vpc_endpoint_route_table_ids=vpc_endpoint_route_table_ids,
        vpc_endpoint_subnet_ids=vpc_endpoint_subnet_ids,
        vpc_endpoint_security_group_ids=vpc_endpoint_security_group_ids,
        vpc_endpoint_tags=vpc_endpoint_tags,
        vpc_endpoint_type=vpc_endpoint_type
        )
        )
    log.info('Added {} to VPC Endpoints'.format(vpc_endpoint_name))


def vpn_gateway(name, values):
    vpn_gateway_name = name.split('.')[1]
    vpn_gateway_tags = {}
    try:
        vpn_gateway_vpc = values["vpc_id"]
    except KeyError:
        vpn_gateway_vpc = ""
        log.info('No VPC ID configured for {} Virtual Gateway'.format(vpn_gateway_name))
    try:
        vpn_gateway_asn = values["amazon_side_asn"]
    except KeyError:
        vpn_gateway_asn = ""
        log.info('No ASN configured for {} Virtual Gateway'.format(vpn_gateway_name))
    try:
        vpn_gateway_az = values["availability_zone"]
    except KeyError:
        vpn_gateway_az = ""
        log.info('No availability zone configured for {} Virtual Gateway'.format(vpn_gateway_name))
    for k, v in values.items():
        if tag_regex.match(k):
            vpn_gateway_tag_dict = tags_builder(k, v)
            vpn_gateway_tags.update(vpn_gateway_tag_dict)
    with open(vpc_outfile, "a+") as output:
        output.write(vpn_gateway_template.render(
        vpn_gateway_name=vpn_gateway_name,
        vpn_gateway_vpc=vpn_gateway_vpc,
        vpn_gateway_az=vpn_gateway_az,
        vpn_gateway_asn=vpn_gateway_asn,
        vpn_gateway_tags=vpn_gateway_tags
        ))
    log.info('Added VPN Gateway {} to vpcs.tf'.format(vpn_gateway_name))


def eip(name, values):
    eip_name = name.split('.')[1]
    try:
        eip_count = name.split('.')[2]
        used_eips.append("{}_{}".format(eip_name, eip_count))
    except IndexError:
        eip_count = values["id"]
    try:
        eip_public_ip4_pool = values["public_ipv4_pool"]
    except KeyError:
        eip_public_ip4_pool = ""
        log.info('No ipv4 pool specified for EIP {}'.format(eip_name))
    eip_fullname = "{}_{}".format(eip_name, eip_count)
    eip_vpc = values["vpc"]
    eip_instance = values["instance"]
    eip_network_interface = values["network_interface"]
    eip_assoc_with_ip = values["private_ip"]

    eip_tags = {}
    for k, v in values.items():
        if tag_regex.match(k):
            eip_tag_dict = tags_builder(k, v)
            eip_tags.update(eip_tag_dict)
    with open(vpc_outfile, "a+") as output:
        output.write(eip_template.render(
        eip_name=eip_fullname,
        eip_vpc=eip_vpc,
        eip_instance=eip_instance,
        eip_network_interface=eip_network_interface,
        eip_assoc_with_ip=eip_assoc_with_ip,
        eip_public_ip4_pool=eip_public_ip4_pool,
        eip_tags=eip_tags
        ))
    log.info('Added {} EIP to vpcs.tf'.format(eip_fullname))


def nat_gateway(name, values):
    nat_gateway_name = name.split('.')[1]
    try:
        nat_gateway_count = name.split('.')[2]
        nat_gateway_fullname = "{}_{}".format(nat_gateway_name, nat_gateway_count)
    except IndexError:
        log.info('No count specified for {}'.format(nat_gateway_name))
        nat_gateway_count = 0
        nat_gateway_fullname = nat_gateway_name
    nat_gateway_allocation_id = values["allocation_id"]
    nat_gateway_subnet_id = values["subnet_id"]
    nat_gateway_tags = {}
    for k, v in values.items():
        if tag_regex.match(k):
            nat_gateway_tag_dict = tags_builder(k, v)
            nat_gateway_tags.update(nat_gateway_tag_dict)
    nat_gateway_returned_name = unique_name_checker(nat_gateway_name, nat_gateway_count, "aws_nat_gateway")
    nat_gateway_fullname = nat_gateway_returned_name
    with open(vpc_outfile, "a+") as output:
        output.write(nat_gateway_template.render(
        nat_gateway_name=nat_gateway_fullname,
        nat_gateway_allocation_id=nat_gateway_allocation_id,
        nat_gateway_subnet_id=nat_gateway_subnet_id,
        nat_gateway_tags=nat_gateway_tags
        ))

    log.info('Added {} NAT Gateway to vpcs.tf'.format(nat_gateway_fullname))


def route(name, values):
    route_name = name.split('.')[1]
    try:
        route_count = name.split('.')[2]
        route_fullname = "{}_{}".format(route_name, route_count)
    except IndexError:
        log.info('No count specified for {}'.format(route_name))
        route_count = 0
        route_fullname = route_name
    route_table_id = values["route_table_id"]
    route_dest_ip4_cidr = values["destination_cidr_block"]
    # route_dest_ip6_cidr = values[""]
    route_egress_gateway_id = values["egress_only_gateway_id"]
    route_gateway_id = values["gateway_id"]
    route_instance_id = values["instance_id"]
    route_nat_gw_id = values["nat_gateway_id"]
    route_network_if_id = values["network_interface_id"]
    try:
        route_transit_gw_id = values["transit_gateway_id"]
    except KeyError:
        route_transit_gw_id = ""
        log.info('No transit gateway specified for {}'.format(route_name))
    route_vpc_peer_id = values["vpc_peering_connection_id"]
    route_tags = {}
    for k, v in values.items():
        if tag_regex.match(k):
            route_tag_dict = tags_builder(k, v)
            route_tags.update(route_tag_dict)
    route_fullname = unique_name_checker(route_name, route_count, "aws_route")
    with open(vpc_outfile, "a+") as output:
        output.write(route_template.render(
        route_name=route_fullname,
        route_table_id=route_table_id,
        route_dest_ip4_cidr=route_dest_ip4_cidr,
        route_egress_gateway_id=route_egress_gateway_id,
        route_gateway_id=route_gateway_id,
        route_instance_id=route_instance_id,
        route_nat_gw_id=route_nat_gw_id,
        route_network_if_id=route_network_if_id,
        route_transit_gw_id=route_transit_gw_id,
        route_vpc_peer_id=route_vpc_peer_id,
        route_tags=route_tags
        ))
    log.info('Added {} Route to vpcs.tf'.format(route_fullname))


def route_table(name, values):
    route_table_name = name.split('.')[1]
    try:
        route_table_count = name.split('.')[2]
        route_table_fullname = "{}_{}".format(route_table_name, route_table_count)
    except IndexError:
        route_table_fullname = route_table_name
    route_table_vpc_id = values["vpc_id"]
    route_table_rule_regex = re.compile("route\.(?!\#)")
    route_table_propagating_vgws_regex = re.compile("propagating_vgws\.(?!\#)")
    route_table_all_routes = {}
    route_table_propagating_vgws = []
    route_table_tags = {}
    try:
        route_table_propagating_vgws = values["propagating_vgws"]
    except KeyError:
        log.info('No propagating VGWs configured for {} Route Table'.format(name))
    for k, v in values.items():
        if route_table_rule_regex.match(k):
            route_table_rule_split = k.split('.')
            route_rule_id = route_table_rule_split[1]
            route_rule_param = route_table_rule_split[2]
            route_table_rule_set = {route_rule_param: v}
            route_table_rule_dict = {route_rule_id: route_table_rule_set}
            try:
                if v not in route_table_all_routes[route_rule_id][route_rule_param]:
                    route_table_all_routes[route_rule_id][route_rule_param].append(v)
            except KeyError:
                try:
                    route_table_all_routes[route_rule_id].update(route_table_rule_set)
                    if v not in route_table_all_routes[route_rule_id][route_rule_param]:
                        route_table_all_routes[route_rule_id][route_rule_param].append(v)
                except:
                    route_table_all_routes.update(route_table_rule_dict)
        elif route_table_propagating_vgws_regex.match(k):
            route_table_propagating_vgws.append(v)
        elif tag_regex.match(k):
            route_table_tag_dict = tags_builder(k, v)
            route_table_tags.update(route_table_tag_dict)
    try:
        route_table_name = route_table_tags["Name"]
    except KeyError:
        log.info('No unique name specified for {}'.format(route_table_name))
    with open(vpc_outfile, "a+") as output:
        output.write(route_table_template.render(
        route_table_name=route_table_name,
        route_table_vpc_id=route_table_vpc_id,
        route_table_all_routes=route_table_all_routes,
        route_table_propagating_vgws=route_table_propagating_vgws,
        route_table_tags=route_table_tags
        ))
    log.info('Added {} Route Table to vpcs.tf'.format(route_table_fullname))


def route_table_association(name, values):
    route_table_assoc_name = name.split('.')[1]
    try:
        route_table_assoc_count = name.split('.')[2]
    except IndexError:
        route_table_assoc_count = 0
    route_table_assoc_fullname = "{}_{}".format(route_table_assoc_name, route_table_assoc_count)
    route_table_assoc_subnet_id = values["subnet_id"]
    route_table_assoc_route_table_id = values["route_table_id"]
    route_table_assoc_fullname = unique_name_checker(route_table_assoc_name, route_table_assoc_count, "aws_route_table_association")
    with open(vpc_outfile, "a+") as output:
        output.write(route_table_association_template.render(
        route_table_assoc_name=route_table_assoc_fullname,
        route_table_assoc_subnet_id=route_table_assoc_subnet_id,
        route_table_assoc_route_table_id=route_table_assoc_route_table_id
        ))
    log.info("Route table association {} added to vpcs.tf".format(route_table_assoc_fullname))


def tags_builder(name, value):
    tag_split = name.split('.')
    tag_name = tag_split[1]
    tag_dict = {tag_name: value}
    return tag_dict


def arn_parser(arn):
    returned_list = []
    chopr = arn.split(':')
    region = chopr[3]
    acct_id = chopr[4]
    returned_list.append(region)
    returned_list.append(acct_id)
    return returned_list


def unique_name_checker(resource_name, resource_count, resource_type):
    resource_fullname = "{}_{}".format(resource_name, resource_count)
    try:
        if resource_fullname in used_resource_names[resource_type]:
            new_fullname = unique_name_maker(resource_name, resource_count, resource_type)
            used_resource_names[resource_type].append(new_fullname)
            return new_fullname
        else:
            log.info('Resource name {} is unique!'.format(resource_fullname))
            try:
                used_resource_names[resource_type].append(resource_fullname)
                return resource_fullname
            except KeyError:
                resource_dict = {resource_type: [resource_fullname]}
                used_resource_names.update(resource_dict)
                return resource_fullname
    except KeyError:
        resource_dict = {resource_type: [resource_fullname]}
        used_resource_names.update(resource_dict)
        return resource_fullname


def unique_name_maker(resource_name, resource_count, resource_type):
    resource_fullname = "{}_{}".format(resource_name, resource_count)
    if resource_fullname in used_resource_names[resource_type]:
        last_resource_used = used_resource_names[resource_type][-1]
        last_resource_count = last_resource_used.split('_')[-1]
        resource_new_count = (int(last_resource_count)+1)
        new_fullname = "{}_{}".format(resource_name, resource_new_count)
        return new_fullname
    else:
        return resource_fullname


state_parser(state_path)
if os.path.exists(state_name):
    subprocess.run("mv *.tf {}".format(state_name), shell=True)
else:
    os.mkdir(state_name)
    subprocess.run("mv *.tf {}".format(state_name), shell=True)