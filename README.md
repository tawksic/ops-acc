# Operational Acceptance

# Documentation
**This tool is still being updated, please see REDACTED for more information.**

## Introduction
The goal of this script is to automate performing Operational Acceptance on a new edge to verify it's ready for production (to be added to the JSON for REDACTED).

## Dependencies
1. Access to the Ops Toolbox

2. In order to initialize, the Subnet Mapper Database (SNM DB) must be populated in it’s entirety. In order to ensure SNM is populated, you must:
   a. Enable Subnet Mapper (-f EnableSNM)
   b. Run Subnet Mapper (-f RunSNM)
   c. Deploy the Static Subnet Map role via the deploy.sh script - “Deploying Changes from the SMS” in REDACTED
     i. To be included in provisioning pending REDACTED


## Developer Dependencies
1. Clone the LiveOps Repo
```
git clone https://github.com/tawksic/ops-acc.git
```
2. Install the requirements
```
pip3 install -r requirements.txt
```
3. Create a `.env` file to set your IDM user like so
```
$ cat .env
remote_user=${IDM_USER} # Replace variable with actual IDM User
```

4. The second point from ## Dependencies


## Usage
```
usage: ops-acc.py [-h] -e EDGE [-l] [-f FUNCTION]

Perform Operational Acceptance testing.

optional arguments:
  -h, --help            show this help message and exit
  -l, --list            Lists out the individual functions you can run using the -f flag
  -f FUNCTION, --function FUNCTION
                        Specify the function to run (i.e. HostAvailable, NetworkStatus, etc..)

Required Arguments:
  -e EDGE, --edge EDGE  short edge host - [a-z]{2}-[a-z]{2}-[a-z0-9]{5,6}
```

Here's examples of how to run script:

```
$ python3 ops-acc.py -e REDACTED # Run the whole script
```

```
$ python3 ops-acc.py -l
Available functions:
- AmazonOriginChecks
- AnalyticsChecks
- AnycastChecks
- Bird6Checks
- BirdChecks
- BirdDownstreamChecks
- BirdProtocolsChecks
- BirdSubnetsChecks
- DataDog
- DisableSNM
- EnableSNM
- FullSequence
- Grafana
- HostAvailable
- NS1Checks
- NetworkConfiguration
- NetworkStatus
- ObtainASN
- ObtainRegion
- PlayTester
- PrintAvailableFunctions
- ProxyRequests
- Resolvers
- RunNS1
- RunSNM
- SNMRoutes
- ServiceStatus
- V6Subnets
- ZabbixAddHostGroup
- ZabbixAddTemplate
- ZabbixGetActiveProblems
- main
```

```
$ python3 ops-acc.py -e REDACTED -f HostAvailable
```

