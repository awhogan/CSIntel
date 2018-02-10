# CSIntel
CrowdStrike Threat Intelligence 


This file will act as a Python API for CrowdStrike's Threat Intelligence API. It was built to make it
easy to use the Intel API. 

This module can be used one of two ways: by executing it directly from the command line or by importing 
it into another script. 

Example 1: 
    
    $> ./CSIntel.py --custid ABC --custkey DEF --day

Example 2:

    #!/usr/bin/python
    import CSIntel
    api_obj = CSIntel.CSIntelAPI(custid, custkey)
    results = api_obj.SearchLastWeek()

To learn more about the functions you can use when importing this file see the included python documentation:


    $> pydoc ./CSIntel.py

You can also see the examples included within for the simple functions that are used to enable
the CLI commands.


usage: CSIntel.py [-h] [--custid CUSTID] [--custkey CUSTKEY]
                  [--perPage PERPAGE] [--Page PAGE] [--write]
                  [--config CONFIG] [--raw] [--debug]
                  (--actor ACTOR | --actors ACTORS | --ip IP | --domain DOMAIN | --report REPORT | --indicator INDICATOR | --label LABEL | --target TARGET | --confidence CONFIDENCE | --killchain KILLCHAIN | --malware MALWARE | --active | --threat THREAT | --domaintype DOMAINTYPE | --iptype IPTYPE | --emailtype EMAILTYPE | --day | --week)
                  [--out {all,indicators,hashes,domains,ips,actors,reports,IfReport}]
                  [--related]

CS Intel API - This program can be executed directly to work with
CrowdStrike's Threat Intel API or be imported into other scripts to use.

optional arguments:
  -h, --help            show this help message and exit
  --custid CUSTID       API Customer ID
  --custkey CUSTKEY     API Customer Key
  --perPage PERPAGE, -p PERPAGE
                        How many indicators per page?
  --Page PAGE           Page number of results to get.
  --write, -w           Write the API config to the file specified by the
                        --config option
  --config CONFIG, -c CONFIG
                        Configuration File Name
  --raw                 Raw JSON, do not print pretty
  --debug, -b           Turn on some debug strings
  --actor ACTOR, -a ACTOR
                        Search for an actor by name
  --actors ACTORS, -s ACTORS
                        Search for a actors by pattern
  --ip IP               Search for an IP address
  --domain DOMAIN       Search for a domain
  --report REPORT       Search for a report name, e.g. CSIT-XXXX
  --indicator INDICATOR, -i INDICATOR
                        Search for an indicator
  --label LABEL, -l LABEL
                        Search for a label
  --target TARGET       Search by Targeted Industry
  --confidence CONFIDENCE
                        Search by Malicious Confidence
  --killchain KILLCHAIN
                        Search by kill chain stage
  --malware MALWARE     Search by malware family
  --active              Get confirmed active indicators
  --threat THREAT       Search by threat type
  --domaintype DOMAINTYPE
                        Search by domain type
  --iptype IPTYPE       Search by IP Type
  --emailtype EMAILTYPE
                        Search by email address type
  --day                 Get all indicators that have changed in 24 hours
  --week                Get all indicators that have changed in the past week
  --out {all,indicators,hashes,domains,ips,actors,reports}, -o {all,indicators,hashes,domains,ips,actors,reports,IfReport}
                        What should I print? Default: all
  --related             Flag: Include related indicators.


## Prerequisites

You must also install the python library "requests."

    pip install requests

## Using from the Command Line
-------

The first step to using this from the Command Line is to make sure you're passing your Customer ID
and your Customer Key. There are two ways you can do this:

1. Pass your Customer ID and Key from the command line:
        `$> ./CSintel.py --custid <Customer ID> --custkey <Customer Key>`
2. Place your Customer ID and Key in a config file to be read by the script. By default the file
    expected is ~/.csintel.ini

In order to create this config file you can either write it explicitly or save the config from the
    command line executation. 
        `$> ./CSintel.py --custid ABCD --custkey EFGH --write`

This will save Customer ID & Key to the default config file (~/.csintel.ini). If you wish to specify
    a different file you can pass that: `--write --config diffFile.ini`

If you want to manually write the config file it follows this layout:

        [CrowdStrikeIntelAPI]
        custid = ABCD
        custkey = EFGH
		perpage = 10

Once you are setup to pass your Customer ID and Key you can start searching the Threat Intel API. 


##Search

Search Options

### Actor(s)
* --actor

Query a specific actor.

The named Actor the indicator is associated with (e.g. Panda, Bear, Spider, etc). The actor list is also represented under the labels list in the JSON data structure.

    --actor rocketkitten

* --actors

Query a pattern and return all actors that match it.

    --actors kitten

###IP

* --ip

Search for an IP address.

This is performed as an indicator search where type specifies IP address. 

###Domain
* --domain

Search for a domain.

This is performed as an indicator search where type specifies domain.

###Report
* --report

Search for a report name and get the indicators associated with it.

The report ID the indicator is associated with (e.g. CSIT-XXXX, CSIR-XXXX, etc). The report list is also represented under the labels list in the JSON data structure.

###Indicator
* --indicator

Possible indicator types, from the following set:

* binary\_string 
* compile\_time 
* device\_name 
* domain
* email\_address 
* email\_subject 
* event\_name 
* file\_mapping 
* file\_name 
* file\_path 
* hash\_ion 
* hash\_md5 
* hash\_sha1 
* hash\_sha256 
* ip\_address 
* ip\_address\_block 
* mutex\_name 
* password 
* persona\_name 
* phone\_number 
* port
* registry 
* semaphore\_name 
* service\_name
* url

###Label
* --label

The Intel API contains additional context around an indicator under the labels list. Some of these labels, such as 'malicious\_confidence' are accessible via the top level data structure. All labels, including their associated timestamps, will be accessible via the labels list.

###Target
* --target

The activity associated with this indicator is known to target the indicated vertical sector, which could be any of:

* Aerospace
* Agricultural
* Chemical
* Defense
* Dissident
* Energy
* Extractive
* Financial
* Government
* Healthcare
* Insurance
* International Organizations 
* Legal
* Manufacturing 
* Media
* NGO 
* Pharmaceutical 
* Research
* Retail 
* Shipping 
* Technology 
* Telecom 
* Transportation 
* Universities

###Confidence
* --confidence

Indicates a confidence level by which an indicator is considered to be malicious. For example, a malicious file hash may always have a value of 'high' while domains and IP addresses will very likely change over time. The malicious confidence level is also represented under the labels list in the JSON data structure.

* High - If indicator is an IP or domain, it has been associated with malicious activity within the last 60 days.
* Medium - If indicator is an IP or domain, it has been associated with malicious activity within the last 60-120 days.
* Low - If indicator is an IP or domain, it has been associated with malicious activity exceeding 120 days.
* Unverified - This indicator has not been verified by a Crowdstrike Intelligence analyst or an automated system.

###Kill Chain
* --killchain

The point in the kill chain at which an indicator is associated. The kill chain list is also represented under the labels list in the JSON data structure. The following italicized entries are sub-labels of the parent kill\_chain.

An example Search is: search for “/labels?match=reconnaissance”

* Reconnaissance
This indicator is associated with the research, identification, and selection of targets by a malicious actor.

* Weaponization
This indicator is associated with assisting a malicious actor create malicious content.

* Delivery
This indicator is associated with the delivery of an exploit or malicious payload.

* Exploitation
This indicator is associated with the exploitation of a target system or environment.

* Installation
This indicator is associated with the installation or infection of a target system with a remote access tool or other tool allowing for persistence in the target environment.

* C2 (Command and Control)
This indicator is associated with malicious actor command and control.

* Actionsonobjectives (Actions on Objectives)
This indicator is associated with a malicious actor's desired effects and goals.


###Malware
* --malware

Indicates the malware family an indicator has been associated with. An indicator may be associated with more than one malware family. The malware family list is also represented under the labels list in the JSON data structure.

###Active
* --active

Status Type contains information tagged in the below italicized list which is broken down by the current status of the indicator.
An example Search is: “/labels?match=confirmedactive”

This indicator is likely to be currently supporting malicious activity

###Threat
* --threat

Threat Type contains information tagged in the below italicized list which is broken down by the type of threat category that was associated with the indicator.
An example Search is: “/labels?match=clickfraud”

* ClickFraud
This indicator is used by actors engaging in click or ad fraud
 
* Commodity
This indicator is used with commodity type malware such as Zeus or Pony Downloader.
PointOfSale
This indicator is associated with activity known to target point-of- sale machines such as AlinaPoS or BlackPoS.
 
* Ransomware
This indicator is associated with ransomware malware such as Crytolocker or Cryptowall.
 
* Suspicious
This indicator is not currently associated with a known threat type but should be considered suspicious.
Targeted
This indicator is associated with a known actor suspected to associated with a nation-state such as DEEP PANDA or ENERGETIC BEAR.
 
* TargetedCrimeware
This indicator is associated with a known actor suspected to be engaging in criminal activity such as WICKED SPIDER.

###Domain Type
* --domaintype 

Domain Type contains information tagged in the below italicized list which is broken down by the type of domain category that was identified.
An example Search is: “/labels?match=actorcontrolled”

* ActorControlled
It is believed the malicious actor is still in control of this domain.
 
* DGA
This domain is the result of malware utilizing a domain generation algorithm.

* DynamicDNS
This domain is owned or used by a dynamic DNS service.
 
* DynamicDNS/Afraid
This domain is owned or used by the Afraid.org dynamic DNS service.
 
* DynamicDNS/DYN
This domain is owned or used by the DYN dynamic DNS service.

* DynamicDNS/Hostinger
This domain is owned or used by the Hostinger dynamic DNS service.
 
* DynamicDNS/noIP
This domain is owned or used by the NoIP dynamic DNS service.
 
* DynamicDNS/Oray
This domain is owned or used by the Oray dynamic DNS service.
 
* KnownGood
The domain itself (or the domain portion of a URL) is known to be legitimate, despite having been associated with malware or malicious activity.
 
* LegitimateCompromised
This domain does not typically pose a threat but has been compromised by a malicious actor and may be serving malicious content.

* PhishingDomain
This domain has been observed to be part of a phishing campaign.

* Sinkholed
The domain is being sinkholed, likely by a security research team. This indicates that, while traffic to the domain likely has a malicious source, the IP address to which it is resolving is controlled by a legitimate 3rd party. It is no longer believed to be under the control of the actor.
 
* StrategicWebCompromise
While similar to the DomainType/LegitimateCompromised label, this label indicates that the activity is of a more targeted nature. Oftentimes, targeted attackers will compromise a legitimate domain that they know to be a watering hole frequently visited by the users at the organizations they are looking to attack.

* Unregistered
The domain is not currently registered with any registrars.

###IP Address Type
* --iptype

IP Address Type contains information tagged in the below italicized list which is broken down by the type of IP category that was identified.
An example Search is: “/labels?match=htrandestinationnode”

* HtranDestinationNode
An IP address with this label is being used as a destination address with the HTran Proxy Tool.
 
* HtranProxy
An IP address with this label is being used as a relay or proxy node with the HTran Proxy Tool.
LegitimateCompromised
It is suspected an IP address with this label is compromised by malicious actors.
 
* Parking
This IP address is likely being used as parking IP address.

* PopularSite
This IP address could be utilized for a variety of purposes and may appear more frequently than other IPs.

* SharedWebHost
This IP address may be hosting more than one website.

* Sinkhole
This IP address is likely a sinkhole being operated by a security researcher or vendor.
 
* TorProxy
This IP address is acting as a TOR (The Onion Router) Proxy

###Email Address Type
* --emailtype

Email Address Type contains information tagged in the below italicized list which is broken down by the type of email category that was identified.
An example Search is: “/labels?match=domainregistrant”

* DomainRegistrant
This email address has been supplied in the registration information for known malicious domains.

* SpearphishSender
This email address has been used to send spearphishing emails.

##Output
 
You can also specify what output you want to receive. By default these methods will pretty print all
JSON received from the API request. Altenatively you can specify:

    --out indicators        -print all indicators
    --out hashes            -print just the hashes
    --out domains           -print just domains
    --out ips               -print just IP addresses
    --out actors            -print any Actors associated with the API request data
    --out reports           -print any reports associated with the API request data
    --out IfReport          -print the raw data in JSON, but only for those indicators that are associated with a published report. 



Examples
==========

Tell me about Rocket Kitten.

    >./CSIntel.py --actor rocketkitten
    ...

Get all intel data that has been updated in the last 24 hours and print all indicators returned
    
    >./CSIntel.py --day --out indicators
    hash_md5:XXXXXXXXXXXXXXXXXXXXXXXXX:Malware/njRAT:MaliciousConfidence/High:
    hash_sha1:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:Malware/njRAT:MaliciousConfidence/High:
    ip_address:XXX.XX.XXX.X:ThreatType/Suspicious:IpAddressType/TorProxy:
    ...

Having found an interesting IP address, search CrowdStrike's API for it and return if any threat
actors have been associated with it.

    >./CSIntel.py --ip XXX.XXX.XXX.XXX --out actors
    WETPANDA

Search the same IP address to see if it has been discussed in any Intelligence Reports.

    >./CSIntel.py --ip XXX.XXX.XXX.XXX --out reports
    CSIR-13017
    CSIT-13051

Search a specified report and print all hashes associated with it

    >./CSIntel.py  --report CSIR-13017 --out hashes
    XXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    XXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    ...

-------------------------------------------------------------------------------------------------------
written by: adam.hogan@crowdstrike.com

Change log
=========
Version 0.8
* PEP8 compliance added by Christophe Vandeplas
* Python 3 compliance added by Christophe Vandeplas
* API v 2 Support
* Deleted option - there is now a command line option to include deleted indicators.

Version 0.7.2
* Added the '--out IfReport' option that will output all returned indicators (in JSON) if they have an associated report.

Version 0.7.1
* Added the --Page option to manually specifcy differnt pages if the number of results is larger than your perPage setting. For real this time.

Version 0.7
* Updated the '--malware' keyword to use direct search instead of a label search.
* First shot at adding Pagination.
    * Added keyword '--perPage' that lets you specify how many results you want.
    * Added keyword '--page' that lets you specify which page of results (if the total number of indicators is greater than your perPage value).

Version 0.6
* Added the '--raw' keyword which will output raw json instead of pretty printed text.

Version 0.5
* Added proxy support using urllib. Proxy settings are automatically read from the OS settings

Version 0.4.1
* Serious bug, identified by Wes Bateman, where every search was a search for confirmed active malware.

Version 0.4
* Changed default location for config file to ~/.csintel.ini
* Check to see if config file exists when it's specified, more detailed errors.
* Added Label search framework
* Added specific functions to search for specific labels:
    * SearchTarget
    * SearchConfidence
    * SearchKillChain
    * SearchMalware
    * SearchActive
    * SearchThreat
    * SearchDomainType
    * SearchIPType
    * SearchEmailType

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



TODO
====

* search by vulnerability
* input validating
* error control
* add proxy server support


-------------------------------------------------------------------------------------------------------
