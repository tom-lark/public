#!/usr/bin/env python3
#-*- coding: utf-8 -*-

### accept arguments for instance name, hosted zone name, dns record name
### only ask for user input if not silent

import argparse
import boto3
from botocore.exceptions import ClientError

is_main_entry = False
is_silent = False
is_verbose = False

def create_ec2_client():
	return boto3.client('ec2')

def create_ec2_resource():
	return boto3.resource('ec2')

def create_route53_client():
	return boto3.client('route53')

def get_hosted_zone_by_index(hosted_zone_index, hosted_zones):
	return hosted_zones[hosted_zone_index]

def get_hosted_zone_record_by_index(a_record_index, hosted_zone_records):
	return hosted_zone_records[a_record_index]

def get_instance_by_index(instance_index, instances):
	key = list(instances)[instance_index]
	return instances[key]

def get_instance_tag(tags, key, default=''):
	if not tags: return default
	for tag in tags:
		if tag['Key'] == key:
			return tag['Value']
	return default

def output(message):
	if is_silent: return
	print(message)

def output_error(message):
	output(message)
	if is_main_entry:
		exit()
	return message

def list_hosted_zones(route53_client):
	response = route53_client.list_hosted_zones_by_name(MaxItems='9999')
	verbose(response)
	hosted_zones = response["HostedZones"]
	max_id = max([len(str(zone['Id'])) for zone in hosted_zones])
	max_name = max([len(str(zone['Name'])) for zone in hosted_zones])
	index = 0
	for zone in hosted_zones:
		id = str(zone['Id']).ljust(max_id)
		name = str(zone['Name']).ljust(max_name)
		output(f"{str(index).ljust(2)} : {id} | {name}")
		index = index + 1
	return hosted_zones

def list_hosted_zone_records(route53_client, hosted_zone):
	response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone['Id'])
	a_records = [x for x in response["ResourceRecordSets"] if x["Type"] == "A" and "ResourceRecords" in x and len(x["ResourceRecords"]) == 1]
	verbose(response)
	a_records.sort(key = lambda x: x["Name"])
	max_name = max([len(str(a_record['Name'])) for a_record in a_records])
	max_ip = max([len(str(a_record['ResourceRecords'][0]['Value'])) for a_record in a_records])
	index = 0
	for a_record in a_records:
		name = str(a_record['Name']).ljust(max_name)
		ip = str(a_record['ResourceRecords'][0]['Value']).ljust(max_ip)
		output(f"{str(index).ljust(2)} : {name} | {ip}")
		index = index + 1
	return a_records

def list_instances(ec2_client):
	response = ec2_client.instances.all()
	verbose(response)
	ec2_instances = [( get_instance_tag(x.tags, 'Name', x.id), x ) for x in response]
	ec2_instances.sort(key = lambda x: x[0])
	instances = { x[0]: x[1] for x in ec2_instances }
	max_key = max([len(key) for key in instances])
	max_id = max([len(str(instances[key].id)) for key in instances])
	max_state = max([len(str(instances[key].state['Name'])) for key in instances])
	max_public_ip_address = max([len(str(instances[key].public_ip_address or '')) for key in instances])
	index = 0
	for key in instances:
		x = instances[key]
		key = key.ljust(max_key)
		id = x.id.ljust(max_id)
		state = x.state['Name'].ljust(max_state)
		public_ip_address = (x.public_ip_address or '').ljust(max_public_ip_address)
		output(f"{str(index).ljust(2)} : {key} | {id} | {state} | {public_ip_address}")
		index = index + 1
	return instances

def parse_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--instance-name", help = "Name of instance to start and copy ip address from, instance requires a name tag")
	parser.add_argument("-r", "--dns-record-name", help = "Name of dns record, ie www.mysite.com")
	parser.add_argument("-s", "--silent", action='store_true', help = "Don't output to console, default False, if True -i, -r, -z are all required")
	parser.add_argument("-v", "--verbose", action='store_true', help = "Output responses from aws")
	parser.add_argument("-z", "--hosted-zone-name", help = "Name of hosted zone to update")
	args = parser.parse_args()
	if args.silent:
		global is_silent
		is_silent = True
		if not args.instance_name or not args.dns_record_name or not args.hosted_zone_name:
			output('missing args')
	if args.verbose:
		global is_verbose
		is_verbose = True
	output(args)
	return args

def start_instance(ec2_client, instance):
	output(f'{instance.id} {instance.state["Name"]}')
	if instance.state['Name'] != "stopped":
		return False
	try:
		ec2_client.start_instances(InstanceIds=[instance.id], DryRun=True)
	except ClientError as e:
		if 'DryRunOperation' not in str(e):
			return output_error(e)
	try:
		response = ec2_client.start_instances(InstanceIds=[instance.id], DryRun=False)
		verbose(response)
	except ClientError as e:
		return output_error(e)
	return True

def update_hosted_zone_record_ip(route53_client, hosted_zone, hosted_zone_record, instance):
	try:
		response = route53_client.change_resource_record_sets(
			HostedZoneId=hosted_zone['Id'],
			ChangeBatch= {
				'Comment': 'changed by tom xps',
				'Changes': [
					{
					'Action': 'UPSERT',
					'ResourceRecordSet': {
						'Name': hosted_zone_record['Name'],
						'Type': 'A',
						'TTL': 300,
						'ResourceRecords': [{'Value': instance.public_ip_address}]
					}
				}]
			})
		verbose(response)
	except ClientError as e:
		return output_error(e)

def validate_user_choice(user_choice, max_index):
	if user_choice == 'q' : exit()
	try:
		instance_index = int(user_choice)
	except:
		return output_error('invalid choice .')
	if instance_index < 0 or instance_index >= max_index:
		return output_error('invalid choice ,')
	return instance_index

def verbose(message):
	if is_verbose: return
	output(message)

def wait_for_instance_to_start(ec2_client, instance):
	output('waiting for instance to start')
	instance_runner_waiter = ec2_client.get_waiter('instance_running')
	instance_runner_waiter.wait(InstanceIds=[instance.id])
	output('instance is started and running')

def wait_user_choice(selection_type):
	output(f"Select {selection_type} index (or q to quit)")
	return input()

if __name__ == '__main__':
	is_main_entry = True
	args = parse_arguments()
	exit()
	ec2_resource = create_ec2_resource()
	instances = list_instances(ec2_resource)
	user_choice = wait_user_choice('instance')
	instance_index = validate_user_choice(user_choice, len(instances))
	instance = get_instance_by_index(instance_index, instances)
	ec2_client = create_ec2_client()
	wait_required = start_instance(ec2_client, instance)
	route53_client = create_route53_client()
	hosted_zones = list_hosted_zones(route53_client)
	user_choice = wait_user_choice('hosted_zone')
	hosted_zone_index = validate_user_choice(user_choice, len(instances))
	hosted_zone = get_hosted_zone_by_index(hosted_zone_index, hosted_zones)
	hosted_zone_records = list_hosted_zone_records(route53_client, hosted_zone)
	user_choice = wait_user_choice('a record')
	a_record_index = validate_user_choice(user_choice, len(hosted_zone_records))
	a_record = get_hosted_zone_record_by_index(a_record_index, hosted_zone_records)
	if wait_required:
		wait_for_instance_to_start(ec2_client, instance)
		instances = list_instances(ec2_resource)
		instance_update = get_instance_by_index(instance_index, instances)
		if instance.id != instance_update.id:
			output_error(f'{instance.id} != {instance_update.id}')
		if instance_update.public_ip_address is None:
			output_error('instance public ip not available')
		instance = instance_update
	update_hosted_zone_record_ip(route53_client, hosted_zone, a_record, instance)
	list_hosted_zone_records(route53_client, hosted_zone)
