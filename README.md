# CSIntel
CrowdStrike Threat Intelligence 

This file will act as a Python API for CrowdStrike's Threat Intelligence API. It was built to make it
easy to use the Intel API. 

This module can be used one of two ways: by executing it directly from the command line or by importing 
it into another script. 

Example 1: 
    
    $> ./CSIntel.py --custid ABC --custkey DEF --day --indicators

Example 2:

    #!/usr/bin/python
    import CSIntel
    api_obj = CSIntel.CSIntelAPI(custid, custkey)
    results = api_obj.SearchLastWeek()

To learn more about the functions you can use when importing this file see the included python documentation:


    $> pydoc ./CSIntel.py

You can also see the examples included within for the simple functions that are used to enable
the CLI commands.

The command line usage is shown below:

     usage: CSIntel.py [-h] [--custid CUSTID] [--custkey CUSTKEY] [--write]
                       [--config CONFIG]
                       (--actor ACTOR | --actors ACTORS | --ip IP | --indicator INDICATOR | --day | --week)
                       [--out {all,indicators,hashes,domains,ips,actors,reports}]
                       [--related]
     
     CS Intel API
     
     optional arguments:
       -h, --help            show this help message and exit
       --custid CUSTID, -i CUSTID
                             API Customer ID
       --custkey CUSTKEY, -k CUSTKEY
                             API Customer Key
       --write, -w           Write the API config to the file specified by the
                             --config option
       --config CONFIG, -c CONFIG
                             Configuration File Name
       --actor ACTOR, -a ACTOR
                             Search for an actor by name
       --actors ACTORS, -s ACTORS
                             Search for a actors by pattern
       --ip IP, -p IP        Search for an IP address
       --domain DOMAIN, -d DOMAIN
                             Search for a domain
       --report REPORT, -r REPORT
                             Search for a report
       --indicator INDICATOR, -n INDICATOR
                             Search for an indicator
       --day                 Get all indicators that have changed in 24 hours
       --week                Get all indicators that have changed in the past week
       --out {all,indicators,hashes,domains,ips,actors,reports}, -o {all,indicators,hashes,domains,ips,actors,reports}
                             What should I print? Default: all
       --related             Include related indicators.

## Using from the Command Line
-------

The first step to using this from the Command Line is to make sure you're passing your Customer ID
and your Customer Key. There are two ways you can do this:

1. Pass your Customer ID and Key from the command line:
        `$> ./CSintel.py --custid <Customer ID> --custkey <Customer Key>`
2. Place your Customer ID and Key in a config file to be read by the script. By default the file
    expected is csintel.ini

In order to create this config file you can either write it explicitly or save the config from the
    command line executation. 
        `$> ./CSintel.py --custid ABCD --custkey EFGH --write`

This will save Customer ID & Key to the default config file (csintel.ini). If you wish to specify
    a different file you can pass that: `--write --config diffFile.ini`

If you want to manually write the config file it follows this layout:

        [CrowdStrikeIntelAPI]
        custid = ABCD
        custkey = EFGH

Once you are setup to pass your Customer ID and Key you can start searching the Threat Intel API. 

    --actor
    --actors
    --ip
    --domain
    --report
    --indicator
    --day
    --week

You can also specify what output you want to receive. By default these methods will pretty print all
JSON received from the API request. Altenatively you can specify:

    --out indicators        -print all indicators
    --out hashes            -print just the hashes
    --out domains           -print just domains
    --out ips               -print just IP addresses
    --out actors            -print any Actors associated with the API request data
    --out reports           -print any reports associated with the API request data



Examples
==========

Tell me about Rocket Kitten.

    >./CSIntel.py --actor rocketkitten
    ...

Get all intel data that has been updated in the last 24 hours and print all indicators returned
    
    >./CSIntel.py --day --out indicators
    hash_md5:297bea792870a2433944a1ea8bcaf196:Malware/njRAT:MaliciousConfidence/High:
    hash_md5:df12de91be850692e24dc6b9ea3f4645:Malware/njRAT:MaliciousConfidence/High:
    hash_sha1:3b9dde2478c42576f87506dfe0aeca921dd42a0f:Malware/njRAT:MaliciousConfidence/High:
    hash_sha1:4952afe964e304a4ab74158b1bf84e1e74ef05cb:Malware/njRAT:MaliciousConfidence/High:
    ip_address:178.67.252.5:ThreatType/Suspicious:IpAddressType/TorProxy:
    ...

Having found an interesting IP address, search CrowdStrike's API for it and return if any threat
actors have been associated with it.

    >./CSIntel.py --ip 211.230.232.221 --out actors
    WETPANDA

Search the same IP address to see if it has been discussed in any Intelligence Reports.

    >./CSIntel.py --ip 211.230.232.221 --out reports
    CSIR-13017
    CSIT-13051

Search a specified report and print all hashes associated with it

    >./CSIntel.py  --report CSIR-13017 --out hashes
    f4971892bdedbff4aa0cc8c63fcf85f2c8bfe364d76769cadd70d128a372a481
    63dbabdf27f92b29597ea4fbeacb1d7fde058d8d
    391b63a12332cdb7384d4183c8693153c683ed8afd6a8933b87a1eea88cb107a
    6ce07e229a91953410ae972343d14e9d9a2afbe1
    ...

-------------------------------------------------------------------------------------------------------
written by: adam.hogan@crowdstrike.com

Change log
=========

Version 0.3
* Added search for report name
* Added documentation examples
* Cleaned up config write

Version 0.2
* Added indicator labels option, and it's availability from the CLI
* Added "related" options to data methods to get indicators related to the original indicators.
Also available from the Command Line with the --related flag.

Version 0.1
* Initial release


###TODO

*search for malware family
*search for labels
*search for target industry
*search for threat type
*search by vulnerability
*input validating
*error control
*add proxy server support

-------------------------------------------------------------------------------------------------------
