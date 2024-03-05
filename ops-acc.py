#!/usr/bin/python3

import os
import re
import pytz
import json
import socket
import atexit
import keyring
import logging
import getpass
import requests
import argparse
import paramiko
import psycopg2
import ipaddress
import subprocess
import pandas as pd
from dotenv import load_dotenv
from datetime import datetime, timedelta


class SSHManager:
  def __init__(self, sudo_password=None):
    self.ssh_clients = {}
    self.remote_sudo_password = sudo_password
    self.remote_user = self.GetRemoteUser()

  def GetRemoteUser(self):
    current_hostname = socket.gethostname()

    if current_hostname == 'REDACTED':
        remote_user = getpass.getuser()
    else:
       load_dotenv()
       remote_user = os.getenv('REDACTED')
    return remote_user

  
  def ConnectSSH(self, remote_host, remote_user=None, remote_port=22):
    if remote_user is None:
      remote_user = self.remote_user
    
    try: 
      if remote_host not in self.ssh_clients or \
        not self.ssh_clients[remote_host].get_transport() or \
        not self.ssh_clients[remote_host].get_transport().is_active():
  
          ssh_client = paramiko.SSHClient()
          ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
          ssh_client.load_system_host_keys()
          ssh_client.connect(remote_host, remote_port, remote_user)
          self.ssh_clients[remote_host] = ssh_client
      return self.ssh_clients[remote_host]
    except TimeoutError:
      OpsAcceptance._PrintRed("The edge is pingable, but timeout received when trying to run a shell command on it. Exiting...")
      exit()


  def ExecSSH(self, command, remote_host, pty_required=False, sudo_required=False):
    client = self.ConnectSSH(remote_host)
    stdin, stdout, stderr = client.exec_command(command, get_pty=pty_required)
    if sudo_required and self.remote_sudo_password is not None:
        stdin.write(self.remote_sudo_password + "\n")
        stdin.flush()
    remote_command_output = stdout.read().decode('utf-8').strip()
    return remote_command_output


  def CloseSSH(self):
    for hostname, client in self.ssh_clients.items():
      client.close()
    self.ssh_clients = {}


class DatabaseManager:
  def __init__(self, host, database, user):
    self.connection_params = {
        'host': host,
        'database': database,
        'user': user,
        'password': keyring.get_password('REDACTED', 'REDACTED')
    }


  def ConnectDB(self, query, edge):
    try:
      with psycopg2.connect(**self.connection_params) as connection:
        with connection.cursor() as cursor:
          cursor.execute(query, edge)
          results = cursor.fetchall()
          columns = [column[0] for column in cursor.description]
      return pd.DataFrame(results, columns=columns)
    except psycopg2.Error as error:
      print(f"Error connecting to the database: {error}")
      exit()


  def QuerySNM(self, edge):
    query = """
      SELECT * 
      FROM SM.EDGE_NODES EN 
      JOIN ISPS I ON I.ID = EN.ISP_ID 
      JOIN POPS P ON P.ID = EN.POP_ID 
      JOIN SUBNET_NETWORK_LOCATION SNL ON SNL.NETWORK_LOC_ID = P.NETWORK_LOC_ID 
      JOIN NETWORK_LOCATIONS NL ON NL.ID = SNL.NETWORK_LOC_ID 
      JOIN SUBNETS S ON S.ID = SNL.SUBNET_ID 
      JOIN ASNS A ON A.ID = S.ASN_ID 
      WHERE en.alt_edge_name = %s;
    """
    try:
        return self.ConnectDB(query, (edge,))
    except Exception as e:
        print(f"An error occurred while querying SNM: {e}")
        exit()


  def QueryAnalytics(self, edge):
    query = """
      SELECT * 
      FROM IMS.EDGE_NODES 
      WHERE EDGE_NAME = %s;
    """
    try:
      return self.ConnectDB(query, (edge,))
    except Exception as e:
        print(f"An error occurred while querying Analytics: {e}")
        exit()

class OpsAcceptance:
  def __init__(self):
    self._SetupArgParser()
    self._SetupLogging()

    self.template_names = ["REDACTED", "REDACTED", "REDACTED"]
    self.host_group_names = ["REDACTED", "REDACTED", "REDACTED", "REDACTED"]

    self.asn_checked = False
    self.host_checked = False

    self.ssh_manager = SSHManager()
    atexit.register(self.ssh_manager.CloseSSH)

    self.HostAvailable()

    self.ObtainRegion()

    snm_manager = DatabaseManager('REDACTED', 'REDACTED', 'REDACTED')
    snm_dict = snm_manager.QuerySNM(self.args.edge)
    self._PopulateSNM(snm_dict)


  def _SetupArgParser(self):
    parser = argparse.ArgumentParser(description='Perform Operational Acceptance testing.')
    parser.add_argument('-e', '--edge', help='short edge host - ef-[a-z]{2}-[a-z0-9]{5,6}')
    parser.add_argument('-l', '--list', action='store_true', help='Lists out the individual functions you can run using the -f flag')
    parser.add_argument('-f', '--function', help='Specify the function to run (i.e. HostAvailable, NetworkStatus, etc..)')
    args = parser.parse_args()

    if args.list:
      self.PrintAvailableFunctions()
      exit()
    elif not args.edge:
      parser.error("The following arguments are required: -e/--edge")
    else:
      self.args = args
      self.state = self.args.edge[3:5]
      self.edge_remote_host = f"REDACTED"
      self.edge_remote_ip = subprocess.run(["dig", "+short", "A", f"REDACTED"], capture_output=True, text=True, check=True).stdout.strip()
      

  def _SetupLogging(self):
      logging.basicConfig(filename='latest-operation-acceptance.log',
                          filemode="w",
                          encoding='utf-8',
                          level=logging.INFO,
                          format="%(asctime)s %(levelname)s: %(message)s")


  def _PrintGreen(self, input_text):
      print("\033[92m{}\033[00m".format(input_text))

  def _PrintYellow(self, input_text):
      print("\033[93m{}\033[00m".format(input_text))

  def _PrintRed(self, input_text):
      print("\033[91m{}\033[00m".format(input_text))


  def _RequireSudo(self):
    if self.ssh_manager.remote_sudo_password is None:
      self.ssh_manager.remote_sudo_password = getpass.getpass("Enter your sudo password: ")


  def _PopulateSNM(self, snm_dict):
    try:
      first_result = snm_dict.iloc[0]
      self.isp_name = first_result.get('isp_name')
      self.ns1_hostname = f"{first_result.get('pop_identifier')}.REDACTED"
      self.peering_group_id = first_result.get('peering_group_id')
      self.subnets = snm_dict.get('prefix', [])
    except IndexError:
      self._PrintRed(f"{self.args.edge} is pingable, but couldn't be found in the SNM DB.")
      if input("Do you want Enable and run SNM? [y/n] : ").lower() == "y":
        self._RequireSudo()
        self.EnableSNM()
        self.RunSNM()
        self._PrintYellow("Deploy the Static Subnet Map role manually, then run -f RunNS1() and try running ops-acc.py again.")
      self._PrintYellow("Exiting..")
      exit() 


  def ObtainRegion(self):
    region = self.ssh_manager.ExecSSH("grep region_name /etc/REDACTED/config.yml | awk '{{print $2}}'", self.edge_remote_ip, False, False)
    if region == "us-prod-sea":
       self.db_region = "us_prod_sea"
       self.ims_region = "sea"
       self.analytics_region = "us-prod"
    elif region == "us-prod-phl":
       self.db_region = "us_prod_phl"
       self.ims_region = "phl"
       self.analytics_region = "us-prod-phl"
    
    self.ims_remote_host = f"REDACTED"
    self.snm_remote_host = "REDACTED"

    return self.db_region, self.ims_region, self.analytics_region, self.ims_remote_host, self.snm_remote_host
  

  def HostAvailable(self):
    response = os.system('ping -c 1 ' + self.edge_remote_host + ' > /dev/null 2>&1')
    
    if self.host_checked == False and response == 0:
      self.host_checked = True
      return
    elif self.host_checked == True and response == 0:
      print(f"\n{self.isp_name} - {self.peering_group_id}:\n----------")
      self._PrintGreen(f"{self.args.edge} responds to pings")
    else:
      self._PrintRed("This edge node doesn't appear to be up as it's not responding to pings. Exiting...")
      exit()
    

  def NetworkStatus(self):
    print("\nNetwork Status:\n----------")
    analytics_manager = DatabaseManager('REDACTED', f'REDACTED', 'REDACTED')
    try:
      analytics_dict = analytics_manager.QueryAnalytics(self.edge_remote_host)
      first_result = analytics_dict.iloc[0]
      op_state = first_result.get('op_state')
      vpn_conn_status = first_result.get('vpn_conn_status')
      latest_heartbeat_at = first_result.get('latest_heartbeat_at')
    except:
      self._PrintRed("One or more values you're expecting in the Analytics database doesn't exist.")
      exit()

    if op_state == "active" and \
    vpn_conn_status == "up" and \
    datetime.now(pytz.timezone('America/Los_Angeles')) - latest_heartbeat_at < timedelta(minutes=2):
      self._PrintGreen("VPN is up and the latest heartbeat is less than 2 minutes ago.")
    else:
      self._PrintRed("Either the VPN is down or the latest heartbeat is older than 2 minutes. See here:")
      print(f"REDACTED")
        
 
  def _AnalyticsRequest(self, analytics_uri):
    analytics_endpoint = "REDACTED"
    uri_dict = {
        "prometheus_metrics": f"/{self.analytics_region}/prometheus/metrics/latest",
        "verify_ims": "/verify/instances",
        "verify_edge": f"/verify/{self.analytics_region}/edges",
        "ims_latest": "/regions/instances/latest",
        "edge_latest": f"/{self.analytics_region}/edges/latest"
    }

    self.analytics_url = analytics_endpoint + uri_dict.get(analytics_uri)
    analytics_response = requests.get(self.analytics_url)
    return analytics_response.json()

  def AnalyticsChecks(self):
    print(f"\nAnalytics/Inventory:\n----------")
    ims_analytics_problems = 0
    edge_analytics_problems = 0

    prom_metrics = self._AnalyticsRequest('prometheus_metrics')
    prom_metrics_count = sum(1 for metric in prom_metrics if metric["host_name"] == f"{self.ims_remote_host}")
    if prom_metrics_count == 12 or prom_metrics_count == 15:
        self._PrintGreen(f"Prometheus metrics are being rolled up to the analytics system for this region: {self.analytics_region}")
    else:
        self._PrintRed(f"Prometheus metrics aren't being rolled up to the analytics system for this region: {self.analytics_region}. \nSee {self.analytics_url}")
  
    verify_ims = self._AnalyticsRequest('verify_ims')
    if 'Verifying all IMSs across all regions recognized by Analytics API-Server at' in verify_ims:
      self._PrintGreen("IMS analytics instances are being recognized by Analytics API-Server")
    else:
      self._PrintRed(f"One or more of the IMS analytics instances aren't recognized by Analytics API-Server")
      ims_analytics_problems = 1
          
    verify_edge = self._AnalyticsRequest('verify_edge')
    if f"Verifying all EDGEs across region [{self.analytics_region}] are recognized by Analytics API-Server at" in verify_edge:
      self._PrintGreen("Edge analytics instances are being recognized by Analytics API-Server")
    else:
      self._PrintRed(f"One or more of the Edge analytics instances aren't recognized by Analytics API-Server")
      edge_analytics_problems = 1
    
    if ims_analytics_problems == 1:
      ims_latest = self._AnalyticsRequest('ims_latest')
      verify_ims_count = sum(1 for metric in ims_latest if metric["ims_full_name"] == f"{self.ims_remote_host}")
      if verify_ims_count == 1:
        self._PrintYellow(f"{self.args.edge} is listed in the IMS's regions, so it's a different IMS that's potentially missing analytics")
      else:
        self._PrintRed(f"{self.args.edge} isn't listed in the IMS's regions. \nSee {self.analytics_url}")
    
    if edge_analytics_problems == 1:
      edge_latest = self._AnalyticsRequest('edge_latest')
      edge_latest_count = sum(1 for edge in edge_latest if edge["edge_full_name"] == f"{self.edge_remote_host}")
      if edge_latest_count == 1:
        self._PrintYellow(f"{self.args.edge} is listed as a latest endpoint, so a different edge is potentially missing analytics")
      else:
        self._PrintRed(f"{self.args.edge} isn\'t listed as a latest endpoint. \nSee {self.analytics_url}")


  def _ZabbixAPICalls(self, method, params):
    zabbix_key = keyring.get_password('zabbix', 'tyler')
    jsonrpc = "2.0"
    zabbix_endpoint = "REDACTED"
    zabbix_headers = {"Content-Type": "application/json"}
    zabbix_payload = {
        "jsonrpc": jsonrpc,
        "method": method,
        "params": params,
        "id": 1,
        "auth": zabbix_key
    }
  
    zabbix_response = requests.post(zabbix_endpoint, data=json.dumps(zabbix_payload), headers=zabbix_headers)
    return zabbix_response.json()

 
  def _ZabbixGetHostID(self):
    get_host_method = "host.get"
    get_hosts_params = { "output": "hostid",
                        "filter": {
                          "host": [ f"{self.edge_remote_host}" ]
                        }
    }
                                  
    host_id_result = self._ZabbixAPICalls(get_host_method, get_hosts_params)

    if 'result' in host_id_result:
        host_id_result = host_id_result['result'][0]['hostid']   
        return host_id_result
    else:
        if host_id_result['error']['code'] == -32602:
            print("Zabbix authentication failed, check your key.")
            exit()
        else:
            raise Exception(host_id_result["error"]["data"])
     
 
  def ZabbixGetActiveProblems(self):
    host_id = self._ZabbixGetHostID()
    get_active_problems_method = "problem.get"
    get_active_problems_params = { "hostids": host_id,
                                   "output": ["name","opdata"],
                                   "sortfield": "eventid",
                                   "sortorder": "DESC"
    }
    problem_result = self._ZabbixAPICalls(get_active_problems_method, get_active_problems_params)

    print(f"\nZabbix:\n----------")
    
    if len(problem_result['result']) == 0:
        self._PrintGreen("There are no open problems!")
    else:
        self._PrintRed(f"Here are the open problems:")
        for problem in problem_result['result']:
            print(f"{problem['name']:55.55}   ---  {problem['opdata']}")
        if not self.args.function or self.args.function.lower() == "all":
          if input("\nDo you want to continue towards adding templates/host groups despite these problems? [y/n] : ").lower() == "y":
              print(f"Continuing...\n")
          else:
              self._PrintRed("Exiting...")
              exit()
 
 
  def _ZabbixGetTemplate(self):
    get_template_method = "template.get"
    get_template_params = { "output": [ "templateid","name" ],
                            "filter": {
                               "host": self.template_names
                            }
    }
    
    get_template_result = self._ZabbixAPICalls(get_template_method, get_template_params)

    returned_template_names = [entry['name'] for entry in get_template_result['result']]
    nonexistent_templates = list(set(self.template_names).difference(returned_template_names))
    if nonexistent_templates:
        self._PrintRed("Counldn\'t find these Zabbix templates:")
        print(f"{', '.join(nonexistent_templates)}.\nExiting...")
        exit()
    else:
        return get_template_result['result']
 
 
  def ZabbixAddTemplate(self):
    host_id = self._ZabbixGetHostID()
    template_id = self._ZabbixGetTemplate()
    add_template_method = "host.update"
    add_template_params = { "hostid": host_id,
                            "templates": template_id
    }

    add_template_result = self._ZabbixAPICalls(add_template_method, add_template_params)

    if 'error' in add_template_result:
        self._PrintRed(f"The {len(self.template_names)} Zabbix Templates were found, but there was an error adding them. \nHere is what we searched for:")
        for template in self.template_names:
          print(template)
        print(add_template_result['error']['message'] + ' ' + add_template_result['error']['data'])
        exit()
    else:
        self._PrintGreen(f"All {len(self.template_names)} Zabbix Templates were found and added to {self.args.edge}")
 
 
  def _ZabbixGetHostGroup(self):
    get_host_group_method = "hostgroup.get"
    get_host_group_params = { "output": "extend",
                              "filter": {
                                "name": self.host_group_names
                              }
    }
  
    get_host_group_result = self._ZabbixAPICalls(get_host_group_method, get_host_group_params)

    returned_host_group_names = [entry['name'] for entry in get_host_group_result['result']]
    nonexistent_host_groups = list(set(self.host_group_names).difference(returned_host_group_names))
    if nonexistent_host_groups:
        self._PrintRed(f"Counldn\'t find these Zabbix host groups:")
        print(f"{', '.join(nonexistent_host_groups)}.\nExiting...")
        exit()
    else:
        return get_host_group_result['result']
 
 
  def ZabbixAddHostGroup(self):
    host_id = self._ZabbixGetHostID()
    host_group_id = self._ZabbixGetHostGroup()
    add_host_group_method = "host.update"
    add_host_group_params = {
            "hostid": host_id,
            "groups": host_group_id
        }
   
    add_host_group_result = self._ZabbixAPICalls(add_host_group_method, add_host_group_params)
   
    if 'error' in add_host_group_result:
        self._PrintRed(f"The {len(self.host_group_names)} Zabbix Host Groups were found, but there was an error adding them. \nHere was the response:")
        print(add_host_group_result['error']['message'] + ' ' + add_host_group_result['error']['data'])
        exit()
    else:
        self._PrintGreen(f"All {len(self.host_group_names)} Zabbix Host Groups were found and added to {self.args.edge}")

 
 
  def ServiceStatus(self):
   print("\nService Status:\n----------")
   service_status_output = self.ssh_manager.ExecSSH("/home/REDACTED/bin/service-status", self.edge_remote_ip)
 
   if service_status_output[-6:] == "All OK":
     self._PrintGreen("All Service Statuses passed")
   else:
     self._PrintRed("The following services failed:")
     for service in (service_status_output.split("\n")):
       if "FAIL" in service:
         print(service)
 

  def PlayTester(self):
   self._RequireSudo()
   print("\nPlay Tester:\n----------")
   play_tester_output = self.ssh_manager.ExecSSH("sudo -S -u netskrt /home/REDACTED/bin/play_test.sh -v | grep -v media_downloader", self.edge_remote_ip, True, True)
 
   if 'Play test completed' in play_tester_output:
     self._PrintGreen("The Play Tester passed")
   elif 'ERROR' in play_tester_output:
     self._PrintRed("The Play Tester failed, here's the output:")
     print(play_tester_output)
   else:
     self._PrintRed(f"Unforeseen Play Tester results, here's the output:")
     print(play_tester_output)


  def _HubspotRequests(self, filters):
    hubspot_key = keyring.get_password('hubspot', 'tyler')
    hubspot_endpoint = "REDACTED"
    hubspot_headers = { 'Content-Type': 'application/json', 
                        'Authorization': hubspot_key }
    hubspot_payload = json.dumps({
      "properties":
        filters
      ,
      "filterGroups": [
        {
          "filters": [
            {
              "propertyName": "tech_hostnames",
              "operator": "CONTAINS_TOKEN",
              "value": self.args.edge
            }
          ]
        }
      ]
    })

    hubspot_response = requests.request("POST", hubspot_endpoint, headers=hubspot_headers, data=hubspot_payload)
    return hubspot_response.json()


  def NetworkConfiguration(self):
    print("\nNetwork Configuration:\n----------")
    network_config = self._HubspotRequests(['tech_interface'])
    config_docs = "REDACTED"

    try:
      num_ports = self.ssh_manager.ExecSSH("cat /sys/class/net/wan0/bonding/ad_num_ports", self.edge_remote_ip)
      is_bonded = 'bond' in network_config['results'][0]['properties']['tech_interface']
      is_aliased = 'alias' in network_config['results'][0]['properties']['tech_interface']
  
      interfaces = self.ssh_manager.ExecSSH("ip link show up | awk -F ': ' '/^[0-9]+:/{print $2}'", self.edge_remote_ip)
      filtered_interfaces = ', '.join(line for line in interfaces.split('\n') if any(net in line for net in ['wan', 'tun0', 'eno1', 'eno2']))
  
      speed = self.ssh_manager.ExecSSH("cat /sys/class/net/wan0/speed", self.edge_remote_ip)
      filtered_speed = ''.join([line for line in speed.split('\n') if "password" not in line])
  
      self._PrintGreen(f"The following interfaces are up: {filtered_interfaces}")
    
      if is_bonded and num_ports == "2" and any(speed in filtered_speed for speed in ['20000','40000']):
        self._PrintGreen(f"This edge is using a bonded configuration currently set to {filtered_speed} Mb/s")
      elif is_aliased and num_ports == "" and any(speed in filtered_speed for speed in ['10000','20000','100000']):
        self._PrintGreen(f"This edge is using a standalone NIC and set to {filtered_speed} Mb/s")
      else:
          self._PrintRed(f"This edge is supposed to be setup as {network_config}, but something is wrong. Please refer here:\n{config_docs}")
  
    except TypeError as e:
        self._PrintRed("Missing network config details. \nAsk CSE to fill out all of the fields in Hubspot.")


  def Resolvers(self): 
    print("\nISP Resolvers:\n----------")
    filters = ['tech_dns_details','tech_dns_type','tech_dns_in_subnet_mapper_']
    resolvers = self._HubspotRequests(filters)

    try:
      if 'not required' in resolvers['results'][0]['properties']['tech_dns_in_subnet_mapper_']:
        self._PrintGreen(f"There are no resolvers, because it uses {resolvers['results'][0]['properties']['tech_dns_type']}")
      else:
        print(resolvers['results'][0]['properties']['tech_dns_details'].replace(", ", "\n"))
    except TypeError:
      self._PrintRed("Missing Resolver details. \nAsk CSE to fill out all of the fields in Hubspot. Exiting...")
      exit() 

  
  def ObtainASN(self):
    self._RequireSudo()
    self.bird_primary_asn = self.ssh_manager.ExecSSH(f"sudo birdc 'show protocols all ISP_peer_0' | grep 'Neighbor AS' | awk '{{print $NF}}'", self.edge_remote_ip, True, True)
    self.filtered_asn = ''.join([line for line in self.bird_primary_asn.split('\n') if "password" not in line])
    self.asn_issues = 0
    self.asn_checked = True
    
    if self.filtered_asn:
      return
    else:
      self._PrintYellow("No ISP_peer_0 found - check with CSE to verify if this is intended")
      self._PrintYellow("If so, confirm everything DNS related manually")
      self.asn_issues = 1


  def Bird6Checks(self):
    v6_check = self._HubspotRequests(['tech_ipv6_address'])
    self.has_ipv6_address = v6_check['results'][0]['properties']['tech_ipv6_address']
    if self.has_ipv6_address and self.args.function == "Bird6Checks":
      self._PrintGreen(f"IPv6 found: {self.has_ipv6_address}")


  def BirdProtocolsChecks(self):
    self._RequireSudo()
    self.Bird6Checks()
  
    def FilterProtocols(protocols):
      filtered = [line for line in protocols.split('\n') if "password" not in line]
      return filtered, all("Established" in line for line in filtered)
  
    v4_protocols = self.ssh_manager.ExecSSH("sudo birdc 'show protocols' | grep BGP", self.edge_remote_ip, True, True)
    v4_filtered, v4_established = FilterProtocols(v4_protocols)
    
    print("- BGP Connections")
    if v4_established:
      self._PrintGreen("All IPv4 BGP connections were established.")
    else:
      self._PrintRed("Not all IPv4 BGP connections were established. See output:")
      for connection in v4_filtered:
        self._PrintRed(connection)
  
    if self.has_ipv6_address:
      v6_protocols = self.ssh_manager.ExecSSH("sudo birdc6 'show protocols' | grep BGP", self.edge_remote_ip, True, True)
      v6_filtered, v6_established = FilterProtocols(v6_protocols)
  
      if v6_established:
        self._PrintGreen("All IPv6 BGP connections were established.")
      else:
        self._PrintRed("Not all IPv6 BGP connections were established. See output:")
        for connection in v6_filtered:
          self._PrintRed(connection)


  def BirdSubnetsChecks(self): 
    self._RequireSudo()
    self.Bird6Checks()

    v4_subnets = self.ssh_manager.ExecSSH("sudo birdc 'show route all' | grep 'ISP' | awk '{print $1}'", self.edge_remote_ip)
    v4_filtered = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', v4_subnets)

    print("- Subnets")
    if v4_filtered:
      self._PrintGreen("IPv4 subnets were found. Here they are:")
      for subnets in v4_filtered:
        print(subnets)
    else:
      self._PrintRed("IPv4 subnets were not found")
  
    if self.has_ipv6_address:
      v6_subnets = self.ssh_manager.ExecSSH("sudo birdc6 'show route all' | grep 'ISP' | awk '{print $1}'", self.edge_remote_ip, True, True)
      v6_filtered = re.findall(r'([a-fA-F0-9:]+:[a-fA-F0-9:]+/[a-zA-Z0-9]+)', v6_subnets)  

      if v6_filtered:
        self._PrintGreen("IPv6 subnets were found. Here they are:")
        for subnets in v6_filtered:
          print(subnets)
      else:
        self._PrintRed("IPv6 subnets were not found")


  def BirdDownstreamChecks(self):
    if self.args.function == "BirdDownstreamChecks":
      self.ObtainASN()
    bird_downstream_asns = self.ssh_manager.ExecSSH(f"sudo birdc 'show route all' | grep 'BGP.as_path' | awk '{{print $NF}}' | grep -v {self.filtered_asn}", self.edge_remote_ip)
    filtered_downstreams = set([line for line in bird_downstream_asns.split('\n') if "password" not in line])

    print("- ASNs")
    if len(filtered_downstreams) == 1:
      self._PrintGreen(f"The primary ASN is {self.filtered_asn}. There are no downstream ASN's")
    else:
      self._PrintYellow(f"The primary ASN is {self.filtered_asn} and the downstream ASN's are:")
      for asn in filtered_downstreams:
        print(asn)


  def BirdChecks(self):
    self.ObtainASN()
    print("\nBird Checks:\n----------")
    if self.asn_issues == 0:
      self.Bird6Checks()
      self.BirdProtocolsChecks()
      self.BirdSubnetsChecks()
      self.BirdDownstreamChecks()
    

  def V6Subnets(self):
    if not self.asn_checked:
      self.ObtainASN()
    if self.asn_issues == 0:
      print("\nIPv6 Subnets:\n----------")
      bgp_tools_endpoint = "REDACTED"
      bgp_tools_headers = {'User-Agent': 'asdasd'}
      bgp_tools_response = requests.get(bgp_tools_endpoint, headers=bgp_tools_headers)
  
      json_data = [json.loads(line) for line in bgp_tools_response.text.strip().split('\n')]
      ipv6_cidrs = [entry["CIDR"] for entry in json_data if entry["ASN"] == self.bird_primary_asn and ":" in entry["CIDR"]]
      collapsed_ipv6_cidrs = list(ipaddress.collapse_addresses(sorted(ipaddress.IPv6Network(cidr) for cidr in ipv6_cidrs)))
      
      if collapsed_ipv6_cidrs:
        for cidr in collapsed_ipv6_cidrs:
            print(cidr)
      else:
        self._PrintGreen("No IPv6 subnets were found from bgp.tools")

    # If you run this 15 or so plus times in 30 minutes,
    # you'll get rate limited for 30 minutes
  

  def SNMRoutes(self):
    print("\nSubnet Mapper Routes:\n----------")
    for subnet in self.subnets:
      print(subnet)


  def NS1Checks(self):
    print("\nNS1 Results:\n----------")
    ns1_key = keyring.get_password('ns1', 'tyler')
    if 'a' <= self.peering_group_id[0].lower() <= 'h':
      zone = "a"
    elif 'i' <= self.peering_group_id[0].lower() <= 'p':
      zone = "b"
    else:
      zone = "c"

    ns1_endpoint = f"REDACTED"
    ns1_headers = {'REDACTED': REDACTED}
    ns1_response = requests.get(ns1_endpoint, headers=ns1_headers)
    ns1_response = ns1_response.json()

    matching_answer = next((answer for answer in ns1_response['answers'] if self.ns1_hostname in answer['answer']), None)
    if matching_answer:
      prefixes = matching_answer['meta']['ip_prefixes']
      for prefix in prefixes:
        print(prefix)
    else:
      self._PrintRed(f"No answers were found in NS1 for {self.ns1_hostname}")


  def EnableSNM(self):
      if input("Would you like to ENABLE Subnet Mapper? (y/n): ").lower() == "y":
        self._RequireSudo()
        print("Enabling...")
        self.enable_subnet_mapper = self.ssh_manager.ExecSSH(f"cd /home/REDACTED/bin; sudo ./subnet-updater-cli.sh ims_edge_nodes -e {self.edge_remote_host} --enable_subnet_mapper t", self.ims_remote_host, True, True)
        print(self.enable_subnet_mapper[26:])
      else:
        self._PrintRed("Exiting...")
        exit()


  def DisableSNM(self):
      if input("Would you like to DISABLE Subnet Mapper? (y/n): ").lower() == "y":
        self._RequireSudo()
        print("Disabling...")
        self.enable_subnet_mapper = self.ssh_manager.ExecSSH(f"cd /home/netskrt/bin; sudo ./subnet-updater-cli.sh ims_edge_nodes -e {self.edge_remote_ip} --enable_subnet_mapper f", self.ims_remote_host, True, True)
        print(self.enable_subnet_mapper[26:])
      else:
        self._PrintRed("Exiting...")
        exit()


  def RunSNM(self): 
    if input("Would you like to RUN Subnet Mapper? (y/n) ").lower() == "y":
      print("Running...")
      self.run_subnet_mapper = self.ssh_manager.ExecSSH(f"curl -X POST REDACTED", self.ims_remote_host)
      print(self.run_subnet_mapper)
    else:
      self._PrintRed("Exiting...")
      exit()


  def RunNS1(self):
    if input("Would you like to RUN NS1 Updater? (y/n) ").lower() == "y":
      print("Running...")
      self.run_subnet_mapper = self.ssh_manager.ExecSSH(f'curl --header "Content-Type: application/json" --request POST --data \'{{"region":"{self.analytics_region}", "edges_to_update":["{self.ns1_hostname}"]}}\' REDACTED', self.snm_remote_host)
      print(self.run_subnet_mapper)
    else:
      self._PrintRed("Exiting...")
      exit()


  def AmazonOriginChecks(self):
   print("\nAmazon Origins:\n----------")
   upstreams = ['REDACTED', 'REDACTED']
   
   for upstream in upstreams:
     amazon_origin_output = self.ssh_manager.ExecSSH(f"ping -c10 {upstream}", self.edge_remote_ip)
     transmitted_lines = [line.strip() for line in amazon_origin_output.split('\n') if 'transmitted' in line]
     packet_loss = re.compile(r"(\d+)% packet loss").search(amazon_origin_output)
     ping_latency = re.compile(r"time (\d+)ms").search(amazon_origin_output)
     if 'transmitted' in  amazon_origin_output and int(packet_loss.group(1)) == 0 and int(ping_latency.group(1)) < 15000:
       self._PrintGreen(f"{upstream:40.40} - {' '.join(transmitted_lines)}")
     elif 'transmitted' not in amazon_origin_output:
       self._PrintRed(amazon_origin_output)
     else:
       self._PrintRed(f"{upstream:40.40} - {' '.join(transmitted_lines)}")
     
 
  def ProxyRequests(self):
   print("\nProxy Requests:\n----------")
   wan0_inet = self.ssh_manager.ExecSSH("ifconfig | grep -A1 wan0 | awk '{print $2}' | tail -n 1", self.edge_remote_ip)
   try:
     curl_check = subprocess.run(['curl', '-s', '-I', '--connect-to', f'REDACTED:443:{wan0_inet}:443', 'https://REDACTED'], capture_output=True, text=True, check=True)
     access_log_check = self.ssh_manager.ExecSSH("awk '$5 ~ /403/ {{print}}' /var/log/nginx/amazon-us-live/access.log", self.edge_remote_ip)
     if '403 Forbidden' in curl_check.stdout and access_log_check.count("403") > 0:
       self._PrintGreen("This Edge can successfully handle proxy requests")
     else:
       self._PrintRed("Unexpected result, please run this manually and review it:")
       print(f"curl -I --connect-to 'REDACTED:443:{wan0_inet}:443' 'https://REDACTED'")
   except subprocess.CalledProcessError as error:
     self._PrintRed(f"Error: {error}")
     self._PrintRed("Unexpected result, please run this manually and review it:")
     print(f"curl -I --connect-to 'REDACTED:443:{wan0_inet}:443' 'https://REDACTED'")

  
  def AnycastChecks(self):
    print("\Anycast:\n----------")
    # To be implemented once we decide how we're going to procede with anycast.
  

  def DataDog(self):
    print("\nDataDog Results:\n----------")
    dd_api_key = keyring.get_password('REDACTED', 'REDACTED')
    dd_app_key = keyring.get_password('REDACTED', 'REDACTED')
    dd_exists = 0
    dd_headers = {
      "Content-Type": "application/json",
      "DD-API-KEY": REDACTED,
      "DD-APPLICATION-KEY": REDACTED
    }
    dd_endpoint = "REDACTED"
    dd_payload = {
      "filter": self.args.edge
    }
    dd_response = requests.get(dd_endpoint, dd_payload, headers=dd_headers)
    dd_response = dd_response.json()

    if dd_response['total_matching'] != 0:
      dd_exists = 1
      self._PrintGreen("This host exists in DataDog.")
    else:
      self._PrintRed("This host doesn't exist in DataDog.")
    
    if dd_exists == 1:
      dd_cpu = dd_response["host_list"][0]["metrics"]["cpu"]
      if dd_cpu > 0:
        self._PrintGreen(f"Values are being rolled up to DataDog. For example, the CPU is {dd_cpu}.")
      else:
        self._PrintRed("Values may not be rolling up to Datadog. Please review the dashboard here: ")
        print(f"REDACTED")
    

  def Grafana(self): 
    print("\nGrafana Results:\n----------")
    self._PrintYellow("Please manually check that data is loading here:")
    print(f"REDACTED")
    input("Is data being visualized? ")

  
  def PrintAvailableFunctions(self):
    print("Available functions:")
    for attribute_name in dir(self):
      if callable(getattr(self, attribute_name)) and not attribute_name.startswith('_'):
        print(f"- {attribute_name}")
  

  def _InvokeFunction(self, function_name):
      function = getattr(self, function_name, None)
      if callable(function):
          function()
      else:
          self._PrintRed("Invalid function (-f) specified.")
          self.PrintAvailableFunctions()
  
  def FullSequence(self):
        self._RequireSudo()
        self.HostAvailable()
        self.NetworkStatus()
        self.AnalyticsChecks()
        self.ZabbixGetActiveProblems()
        self.ZabbixAddTemplate()
        self.ZabbixAddHostGroup()
        self.ServiceStatus()
        self.PlayTester()
        self.NetworkConfiguration()
        self.Resolvers()
        self.BirdChecks()
        self.V6Subnets()
        self.SNMRoutes()
        self.NS1Checks()
        self.AmazonOriginChecks()
        self.ProxyRequests()
        self.DataDog()
        self.Grafana()
  

  def main(self):
    if self.args.function:
        self._InvokeFunction(self.args.function)
    else:
        self.FullSequence()


if __name__ == '__main__':
  ops_acceptance = OpsAcceptance()
  ops_acceptance._SetupArgParser()
  ops_acceptance.main()