#!/usr/bin/env python3

import requests
try:        # python3
    from configparser import SafeConfigParser
except Exception:     # python2
    from ConfigParser import SafeConfigParser
try:        # python3
    from urllib.parse import urlencode
except Exception:
    from urllib import urlencode
from datetime import datetime, timedelta
import os
try:        # python3
    import urllib.request as urllib
except Exception:     # python2
    import urllib

from collections import Counter


# Global
CSconfigSection = "CrowdStrikeIntelAPI"
#host = "https://intelapi.crowdstrike.com/indicator/v2/search/"
host = "https://intelapi.crowdstrike.com/"
indicatorPath = "indicator/v2/search/"
malqueryPath = "malquery/"
reportsPath = "reports/"
defaultConfigFileName = os.path.join(os.path.expanduser("~"), ".csintel.ini")

# setup
__author__ = "Adam Hogan"
__email__ = "adam.hogan@crowdstrike.com"
__version__ = '0.9b'

# I should do more with this....
# These specs from the API documentation should be used to do more input validation
validType = ['binary_string', 'compile_time', 'device_name', 'domain', 'email_address', 'email_subject', 'event_name', 'file_mapping', 'file_name', 'file_path', 'hash_ion', 'hash_md5', 'hash_sha1', 'hash_sha256', 'ip_address', 'ip_address_block', 'mutex_name', 'password', 'persona_name', 'phone_number', 'port', 'registry', 'semaphore_name', 'service_name', 'url', 'user_agent', 'username', 'x509_serial', 'x509_subject']
validParameter = ['sort', 'order', 'last_updated', 'perPage', 'page']
validSearch = ['indicator', 'actor', 'report', 'actor', 'malicious_confidence', 'published_date', 'last_updated', 'malware_family', 'kill_chain', 'domain_type']
validDomainType = ['Actor Controlled', 'DGA', 'DynamicDNS', 'DynamicDNS/Afraid', 'DynamicDNS/DYN', 'DynamicDNS/Hostinger', 'DynamicDNS/noIP', 'DynamicDNS/Oray', 'KnownGood', 'LegitimateCompromised', 'PhishingDomain', 'Sinkholed', 'StragegicWebCompromise', 'Unregistered']
validFilter = ['match', 'equal', 'gt', 'gte', 'lt', 'lte']
validSort = ['indicator', 'type', 'report', 'actor', 'malicious_confidence', 'published_date', 'last_updated']


# local methods
def readConfig(fileName=None):
    """this method is usef for initial creation and can be called
    before an API object is created. Just pass it the filename
    to read an existing config file."""

    # check file exists
    if (os.path.exists(fileName)) is False:
        raise Exception("Config file does not exist: " + fileName)

    # read config file
    parser = SafeConfigParser()
    parser.read(fileName)

    # get var [custid, custkey]
    section = CSconfigSection
    custid = parser.get(section, "custid")
    custkey = parser.get(section, "custkey")
    perpage = parser.get(section, "perpage")

    # TODO might need error checking on what is or isn't being pulled
    # from the file down the road.

    return (custid, custkey, perpage)
# end readConfig()


######################################################################
class CSIntelAPI:
    """
    Class for interacting with CrowdStrike Intel API

    This class object is used in this program if called directly or can be imported
    into another script to use it's methods to search the threat intel API and process
    the data returned.

    Check out functions that start with Search* to see different methods of pulling data.

    Check out functions that like Get*FromResults to see different exampels of processing
    the JSON data that is returned from an API search.

    To create this object you need to pass your Customer ID and Cutomer Key. If you're
    going to be reusing this at all it is much faster to add your ID & Key to a config
    file to be read by this script. The default config file is ~/.csintel.ini.

    If you have a config file then creating an API object is easy.

        import CSIntel
        (custid, custkey) = CSIntel.readConfig()
        api_obj = CSIntel.CSIntelAPI(custid, cutkey)

    Now you can search for data - for eample, data on an adversary we've been tracking.

        results - api_obj.SearchActorEqual("putterpanda")

    And then manipulate the results.

        data = json.loads(result.text)

    Or use some of the built in methods.

        hashes = api_obj.GetHashesFromResults(data)
    """

    def __init__(self, custid=None, custkey=None, perpage=None, page="1", deleted=False, debug=False):
        """
        Intit funciton for the CS Intel API object - pass it the API customer ID and
        customer key to create it.
        Optional: whether the config should be written to disk as a config ini file.
        If the config file is being used check out the readConfig() function to grab
        those fields before creating this object.
        """

        # customer id and key should be passed when obj is created
        self.custid = custid
        self.custkey = custkey

        # pull some global settings for object reference
        self.configSection = CSconfigSection  # config file section title
        self.host = host                      # hostname of where to query API
        self.indicatorPath = indicatorPath
        self.malqueryPath = malqueryPath
        self.reportsPath = reportsPath
        self.perpage = perpage
        self.page = page
        self.deleted = deleted

        # set API valid terms
        # should be used more for syntax validation.
        self.validType = validType
        self.ValidParameter = validParameter
        self.validSearch = validSearch
        self.validFilter = validFilter
        self.validSort = validSort
        self.validDomainType = validDomainType

        # debug?
        self.debug = debug

    # end init

    def writeConfig(self, fileName=None):
        """
        This script supports reading the API config data from a
        configuration file instead of passing it as CLI options.
        That file can easily be written manually, but if you use
        this script it can also write the config file from the options
        you have loaded.
        """

        # setup
        section = self.configSection  # config section to use
        parser = SafeConfigParser()   # create object from ConfigParser library import

        # create config file data
        # create proper section and then add customer id and key as entries.
        parser.add_section(section)
        parser.set(section, 'custid', self.custid)
        parser.set(section, 'custkey', self.custkey)
        parser.set(section, 'perpage', self.perPage)

        # write to disk
        f = open(fileName, "w")
        parser.write(f)
        f.close()
    # end writeConfig()

    def getHeaders(self):
        """
        Need to pass customer id and key as headers.
        This will return the correct syntax to do so. These fields need to be
        passed as headers and not in the URL request itself.
        headers = {'X-CSIX-CUSTID': custid, 'X-CSIX-CUSTKEY': custkey}
        """
        headers = {'X-CSIX-CUSTID': self.custid, 'X-CSIX-CUSTKEY': self.custkey}
        # this is the format needed by the requests module
        return headers
    # end getHeaders

    #def request(self, query):
    def request(self, query, queryType="indicator"):
        """
        This function was intended as an internal method - it just takes the query
        you pass it and sends it to the API along with your API ID & Key. If you
        know the API or rest real well have at it.

        """

        if not self.custid or not self.custkey:
            raise Exception('Customer ID and Customer Key are required')

        fullQuery = self.host

        #Host + Intel API type (e.g. indicator, malquery)
        if queryType == "indicator":
            fullQuery += self.indicatorPath
        elif queryType == "reports":
            fullQuery += self.reportsPath
        elif queryType == "malquery":
            fullQuery += self.malqueryPath

        #TODO else error checking

        #Specific query
        fullQuery += query   

        if self.debug:                  # Show the full query URL in debug
            print("fullQuery: " + fullQuery)

        headers = self.getHeaders()     # format the API key & ID

        # check for proxy information
        proxies = urllib.getproxies()

        # use requests library to pull request
        r = requests.get(fullQuery, headers=headers, proxies=proxies)

        # Error handling for HTTP request

        # 400 - bad request
        if r.status_code == 400:
            raise Exception('HTTP Error 400 - Bad request.')

        # 404 - oh shit
        if r.status_code == 404:
            raise Exception('HTTP Error 404 - awww snap.')

        # catch all?
        if r.status_code != 200:
            raise Exception('HTTP Error: ' + str(r.status_code))

        return r
    # end request()

    def getURLParams(self, **kwargs):
        """
        This funciton takes a series of keyword arguments and then
        encodes them all in a single URL string.
        """

        query = urlencode(kwargs)
        return query

    def getActorQuery(self, actor, searchFilter="equal", **kwargs):
        """
        A specific API query - provide an actor name to retrieve data
        on that actor from the intel API.
        First optional argument is "searchFilter" which defaults to
        "equal" for an exact match (e.g. Putter Panda) but you can use
        searchFilter="match" instead to search for a pattern (e.g.
        panda).
        Any other keywords passed to the function will be encoded in the
        URL request - in case you want to filter or sort, for example.
        """

        valid = ["match", "equal"]
        if searchFilter not in valid:
            raise Exception("not a valid search filter: " + searchFilter)

        encodedargs = ""

        if any(kwargs):
            encodedargs = "&" + self.getURLParams(**kwargs)

        query = "actor?" + searchFilter + "=" + actor + encodedargs

        return query
    # end getActorQuery

    def SearchActorEqual(self, actor, **kwargs):
        """
        A specific use of getActorQuery() to match a specific actor and
        perform the search and return the results found.
        Any other keywords passed to the function will be encoded in the
        URL request - in case you want to filter or sort, for example.
        """
        query = self.getActorQuery(actor, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)
        return result

    def SearchActorMatch(self, actor, **kwargs):
        """
        A specific use of getActorQuery() to match actors matching a pattern.
        The API will be queried and will return the results found.
        Any other keywords passed to the function will be encoded in the
        URL request - in case you want to filter or sort, for example.
        """
        query = self.getActorQuery(actor, searchFilter="match", perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)
        return result

    def getIndicatorQuery(self, indicator, searchFilter="equal", **kwargs):
        """
        This function builds a URL query to search for an indicator. The
        indicator string is what to search for. The searchFilter allows you
        specific match or equal. Any other keyword attributes passed will also
        be encoded as parameters.
        """
        encodedargs = ""

        if any(kwargs):
            # extra keyword arguments get passed - use to sort, filter.
            encodedargs = "&" + self.getURLParams(**kwargs)

        query = "indicator?" + searchFilter + "=" + indicator + encodedargs

        return query
    # end getIndicatorQuery

    def SearchIndicatorEqual(self, indicator, **kwargs):
        """
        Search the API for an indicator.
        Any other keyword arguments passed here will be encoded in the URL
        """

        # build URL query
        query = self.getIndicatorQuery(indicator, perPage=self.perpage, include_deleted=self.deleted, **kwargs)
        # search API
        result = self.request(query)
        # return results
        return result
    # end SearchIndicatorEqual()

    def SearchIndicatorMatch(self, indicator, **kwargs):
        """
        Search the API for an indicator pattern.
        """

        query = self.getIndicatorQuery(indicator, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)
        return result
    # end SearchIndicatorMatch()

    def SearchIP(self, ip):
        """
        Search the API for an IP address
        """

        query = self.getIndicatorQuery(ip, searchFilter="match", type='ip_address', perPage=self.perpage, include_deleted=self.deleted)
        result = self.request(query)
        return result
    # end SearchIP()

    def SearchDomain(self, domain):
        """
        Search the API for a domain
        """

        query = self.getIndicatorQuery(domain, searchFilter="match", type='domain', perPage=self.perpage, include_deleted=self.deleted)
        result = self.request(query)
        return result
    # end SearchDomain()

    def SearchMutex(self, mutex):
        """
        Search the API for a Mutex name
        """

        query = self.getIndicatorQuery(mutex, searchFilter="match", type='mutex_name', perPage=self.perpage)
        result = self.request(query)
        return result
    # end SearchMutex()

    def SearchHash(self, myhash):
        """
        Search the API for a file hash.
        The function will use the length of the hash string to limit the API
        query to a specific type of hash (i.e. MD5, SHA-1, SHA-256.
        """

        # get length of hash and figure out what type it is
        hash_len = len(myhash)
        if hash_len == 32:
            htype = 'hash_md5'
        elif hash_len == 40:
            htype = 'hash_sha1'
        elif hash_len == 64:
            htype = 'hash_sha256'
        else:
            raise Exception("You sure that hash was right?")

        # build query to search for hash by type
        query = self.getIndicatorQuery(myhash, type=htype, perPage=self.perpage)
        # search API
        result = self.request(query)
        return result
    # end SearchHash()

    def getLastUpdatedQuery(self, date, searchFilter, **kwargs):
        """
        Build a query to get changes before/after date argument
        The searchfilter defaults to greater than or equal to the time passed.
        """

        encodedargs = ""

        if any(kwargs):
            # extra keyword arguments get passed - use to sort, filter.
            encodedargs = self.getURLParams(**kwargs)

        query = "last_updated?" + searchFilter + "=" + str(date) + "&" + encodedargs

        if self.debug:
            print("query: " + query)

        return query
    # end getLastUpdatedQuery

    def SearchLastUpdated(self, date, searchFilter="gte", **kwargs):
        """
        Get API updates before or after the date specified and return the results
        Extra keyword arguments are passed so you can sort, etc.
        """

        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter for last_updated")

        query = self.getLastUpdatedQuery(date, searchFilter, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)

        result = self.request(query)

        return result
    # end SearchDate()

    def getEpochDaysAgo(self, days):
        """
        Pass this function an interger n and this function will return
        the epoc time for n days ago.
        getEpochDaysAgo(1), for example, returns the epoch time for
        yesterday (24 hours ago).
        """

        # get datetime object for n days ago.
        daysago = datetime.now() - timedelta(days=days)

        # convert that to standard unix time, ust int() to chop off decimal.
        etime = int((daysago - datetime(1970, 1, 1)).total_seconds())

        # return number of seconds
        return etime

    def SearchLastDay(self, **kwargs):
        """
        Pull any Intel data that has been updated in the last 24 hours
        """

        etime = self.getEpochDaysAgo(1)

        result = self.SearchLastUpdated(etime, **kwargs)

        return result
    # end SearchLastDay()

    def SearchLastWeek(self, **kwargs):
        """
        Pull any Intel data that has been updated in the last week.
        """

        etime = self.getEpochDaysAgo(7)

        result = self.SearchLastUpdated(etime, **kwargs)

        return result
    # end SearchLastWeek()

    def GetReportQuery(self, report, searchFilter, **kwargs):
        """
        Build an API query to search by report name.
        Must pass it a report name as a string.
        I assume searchFilter is equal OR match but come to think of it I've
        only tested "equal."
        Other keyword arguments can be passed to include sorting etc.
        Returns a string for the URL query search.
        """
        # TODO - match reports??
        encodedargs = ""

        if any(kwargs):
            # extra keyword arguments get passed - use to sort, filter.
            encodedargs = "&" + self.getURLParams(**kwargs)

        # build the query string
        query = "report?" + searchFilter + "=" + report + encodedargs

        return query
    # end GetReportQuery()

    def SearchReport(self, report, searchFilter="equal", **kwargs):
        """
        Search the API for a specific report.
        Pass the report name as a string, and any other options.
        Returns the results of the API query.
        """
        query = self.GetReportQuery(report, searchFilter, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)

        return result
    # end SearchReport()

    def SearchTarget(self, target, searchFilter="match", **kwargs):
        """
        Search the API for a specific Target Industry.
        Pass the industry name as a string, and any other options.
        Returns the results of the API query.
        """

        # validate target
        validTarget = ['Aerospace', 'Agricultural', 'Chemical', 'Defense', 'Dissident', 'Energy', 'Extractive', 'Financial', 'Government', 'Healthcare', 'Insurance', 'International Organizations', 'Legal', 'Manufacturing', 'Media', 'NGO', 'Pharmaceutical', 'Research', 'Retail', 'Shipping', 'Technology', 'Telecom', 'Transportation', 'Universities']
        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter")
        if target not in validTarget:
            raise Exception("Invalid target industry")

        # append industry
        label = "Target/" + target

        query = self.GetLabelQuery(label, searchFilter, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)

        return result
    # end SearchTarget()

    def GetLabelQuery(self, label, searchFilter, **kwargs):
        """
        Build an API query to serach by Label.
        Must pass it a label as a string.

        Labels are a generic framework for attaching metadata to an intel
        indicator. See the documentation for full capabilities.

        Other keyword arguments can be passed to include sorting etc.
        Returns a string for the URL query search
        """

        # good query: search/labels?match=Retail

        encodedargs = ""

        if any(kwargs):
            # extra keyword arguments get passed - used to sort, filter.
            encodedargs = "&" + self.getURLParams(**kwargs)

        # build the query string
        query = "labels?" + searchFilter + "=" + label + encodedargs

        return query
    # end GetLabelQuery

    def SearchLabel(self, label, searchFilter="match", **kwargs):
        """
        Search the API for a specific Label
        Pass the label as a string, and any other options.
        Returns the results of the API query.

        Labels are a generic framework for attaching metadata to an intel
        indicator. See the documentation for full capabilities or checkout
        the functions that call this one.

        You can search the entirel label, with the forward slash.
        For example, MaliciousConfidence/High

        """

        # validate
        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter")

        query = self.GetLabelQuery(label, searchFilter, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)

        return result
    # end SearchLabel()

    def SearchConfidence(self, confidence, searchFilter="match", **kwargs):
        """
        Search the API by Malicious Confidence.
        Pass the level (high, medium, low, unverified) as a string,
        and any other options.
        Returns the results of the API query.
        """

        # validate target
        validConfidence = ['high', 'medium', 'low', 'unverified']
        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter")
        if confidence not in validConfidence:
            raise Exception("Invalid confidence level: " + confidence)

        # append industry
        label = "MaliciousConfidence/" + confidence

        query = self.GetLabelQuery(label, searchFilter, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)

        return result
    # end SearchConfidence()

    def SearchKillChain(self, chain, searchFilter="match", **kwargs):
        """
        Search the API by Kill Chain stage.
        Pass the level as a string,
        and any other options.
        Returns the results of the API query.
        """

        # validate parameters
        validKillChain = ['reconnaissance', 'weaponization', 'delivery', 'exploitation', 'installation', 'c2', 'actionsonobjectives']
        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter")
        if chain not in validKillChain:
            raise Exception("Invalid kill chain link: " + chain)

        # append chain to label type
        label = "kill_chain/" + chain

        query = self.GetLabelQuery(label, searchFilter, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)

        return result
    # end SearchKillChain()

    def SearchMalware(self, malware, searchFilter="match", **kwargs):
        """
        Search the API by malware family.
        Pass the level as a string,
        and any other options.
        Returns the results of the API query.
        """

        # validate parameters
        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter")

        encodedargs = ""
        if any(kwargs):
            encodedargs = "&" + self.getURLParams(**kwargs)

        query = "malware_family?" + searchFilter + "=" + malware + encodedargs

        result = self.request(query)

        return result
    # end SearchMalware()

    def SearchActive(self, searchFilter="match", **kwargs):
        """
        Search the API for indicators confirmed active
        Pass the search filter
        and any other options.
        Returns the results of the API query.
        """

        # validate parameters
        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter")

        # append chain to label type
        label = "confirmedactive"

        query = self.GetLabelQuery(label, searchFilter, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)

        return result
    # end SearchActive()

    def SearchThreatType(self, threat, searchFilter="match", **kwargs):
        """
        Search the API by threat type
        Pass the level as a string,
        and any other options.
        Returns the results of the API query.
        """

        # validate parameters
        validThreat = ['ClickFraud', 'Commodity', 'PointOfSale', 'Ransomware', 'Suspicious', 'Targeted', 'TargetedCrimeware', 'Vulnerability']
        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter")
        if threat not in validThreat:
            raise Exception("Invalid Threat type: " + threat)

        # append chain to label type
        label = "ThreatType/" + threat

        query = self.GetLabelQuery(label, searchFilter, **kwargs)
        result = self.request(query)

        return result
    # end SearchThreatType()

    def SearchDomainType(self, domain, searchFilter="match", **kwargs):
        """
        Search the API by domain type
        Pass the level as a string,
        and any other options.
        Returns the results of the API query.
        """

        # validate parameters
        validType = ['ActorControlled', 'DGA', 'DynamicDNS', 'DynamicDNS/Afraid', 'DynamicDNS/DYN', 'DynamicDNS/Hostinger', 'DynamicDNS/noIP', 'DynamicDNS/Oray', 'KnownGood', 'LegitimateCompromised', 'PhishingDomain', 'Sinkholed', 'StrategicWebCompromise', 'Unregistered']
        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter")
        if domain not in validType:
            raise Exception("Invalid Domain type: " + domain)

        # append chain to label type
        label = "DomaintType/" + domain

        query = self.GetLabelQuery(label, searchFilter, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)

        return result
    # end SearchDomainType()

    def SearchEmailType(self, email, searchFilter="match", **kwargs):
        """
        Search the API by email address type
        Pass the email address type as a string,
        and any other options.
        Returns the results of the API query.
        """

        # validate parameters
        validType = ['DomainRegistrant', 'SpearphishSender']
        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter")
        if email not in validType:
            raise Exception("Invalid email type: " + email)

        # append chain to label type
        label = "EmailAddressType/" + email

        query = self.GetLabelQuery(label, searchFilter, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)

        return result
    # end SearchEmailType()

    def SearchIPType(self, iptype, searchFilter="match", **kwargs):
        """
        Search the API by ip address type
        Pass the ip address type as a string,
        and any other options.
        Returns the results of the API query.
        """

        # validate parameters
        validType = ['HtranDestinationNode', 'HtranProxy', 'HtranProxy', 'LegitimateCompromised', 'Parking', 'PopularSite', 'SharedWebHost', 'Sinkholed', 'TorProxy']
        if searchFilter not in self.validFilter:
            raise Exception("Invalid search filter")
        if iptype not in validType:
            raise Exception("Invalid email IP type: " + iptype)

        label = iptype

        query = self.GetLabelQuery(label, searchFilter, perPage=self.perpage, page=self.page, include_deleted=self.deleted, **kwargs)
        result = self.request(query)

        return result
    # end SearchIPType()

    def GetMQDownloadQuery(self, filehash, **kwargs):
        #Model query:
        #GET https://intelapi.crowdstrike.com/malquery/download/v1/<filehash>

        #TODO error checking on filehash

        # build the query string
        query = "download/v1/" + filehash

        return query
    #end GetMQDownloadQuery

    def MQDownloadHash(self, filehash, **kwargs): 
        # Search malquery by file hash to download the sample
        query = self.GetMQDownloadQuery(filehash, **kwargs)

        result = self.request(query, queryType="malquery")
        return result

    # end MQDownloadHash

    def GetReportId(self, report):
        #/reports/queries/reports/v1?name=CSIT-18178
        query = "queries/reports/v1?name=" + report

        searchResult= self.request(query, queryType="reports")

        data = json.loads(searchResult.text)
        ids = data['resources'][0] #TODO could return more than one...

        return ids

    def GetReportDownloadJSONQuery(self, report):
        #entities/reports/v1?ids=40535
        reportId = self.GetReportId(report)
        query = "entities/reports/v1?ids=" + reportId
        return query

    def GetReportDownloadPDFQuery(self, report):
        #entities/report-files/v1?ids=40535
        reportId = self.GetReportId(report)
        query = "entities/report-files/v1?ids=" + reportId
        return query

    def GetReportJSON(self, report, **kwargs):
        reportId = self.GetReportId(report)
        query = self.GetReportDownloadJSONQuery(reportId, **kwargs)

        result = self.request(query, queryType="reports")
        return result

    def GetReportPDF(self, report, **kwargs):
        query = self.GetReportDownloadPDFQuery(report, **kwargs)

        result = self.request(query, queryType="reports")
        return result

# ===================================
# Output
# ===================================

    def GetHashesFromResults(self, result, related=False):
        """
        Give this function results from an API query and it will pull out
        all of the hashes from indicators in those results and return them as a list
        of hashes.
        Also takes the option to include indicators from the relations section. This
        is off by default.
        """

        hashes = []
        # loop through json
        for item in result:
            itype = item['type']
            if itype.find("hash") >= 0:
                # If the indicator is a hash, add it do the list
                hashes.append(item['indicator'])
            if related:
                # are we doing related indicators too?
                for relation in item['relations']:
                    itype = relation['type']
                    if itype.find("hash") >= 0:
                        # if it's a hash, add it to the list.
                        hashes.append(relation['indicator'])

        # return list of hashes
        return hashes
    # end GetHashesFromResults()

    def GetIndicatorsFromResults(self, result, labels=True, related=False):
        """
        Give this function results from an API query and it will pull out
        all of the indicators and return them as a list.
        The labels option will include all the label strings tied to that
        indicator. Each label will be added to the same line but deliminated
        with a colon. This is enabled by default.
        This funciton is intended to be much more verbose with its indicators than
        others, since it's returning all types. So this will tell you the type,
        the indicator, and any labels.
        If you just want the simple list check other funcitons.
        Also takes the option to include indicators from the relations section. This
        is off by default. These indicators are labeled as related.
        """

        indicators = []
        for item in result:
            # loop through each JSON object
            la = ":"
            # format: type:indicator:(labels)
            x = item['type'] + ":" + item['indicator']
            if labels:
                # if labels are included then grab them and add them
                # to the string we're building here.
                for label in item['labels']:
                    # loop through each label and add it.
                    la += label['name']
                    la += ":"  # deliminator

            if related:
                # are we including related indicators?
                for relation in item['relations']:
                    # loop through each item in relations
                    y = relation['type'] + ":" + relation['indicator'] + ":related"
                    # add it to the list
                    indicators.append(y)
            x += la  # add labels
            # add to list
            indicators.append(x)

        # return list of strings
        return indicators
    # end GetIndicatorFromResults()

    def GetReportsFromResults(self, result):
        """
        Pass this funciton results pulled from the API and it will return
        any report names associated with the indicators you have.
        If you have an indicator or maybe a threat actor you're working with
        you can use this to see if there are written reports you should also
        check out.
        """

        reports = []
        for item in result:
            # loop through each JSON indicator
            r = item['reports']
            # does it have anything in the reports section?
            if r:
                for x in r:
                    # if it exists, add each item in the list of reports
                    # to our list
                    reports.append(x)

        # return list of strings of reports
        return reports
    # end GetReportsFromResults()

    def GetDomainsFromResults(self, result, related=False):
        """
        Pass this function results pulled from the API and it will return
        any domains that were included in the list of indicators.
        The related option will include any indicators that are related
        to the primary indicators returned from your API search.
        This returns a simple list of domains, one per line. Want to collect
        domains to feed into your proxy to block?
        """

        domains = []
        # loop through each JSON object
        for item in result:
            # check each indicator to see if the type is domain
            if item['type'] == "domain":
                # add domains to the list
                domains.append(item['indicator'])

            if related:
                # should we include related indicators?
                for relation in item['relations']:
                    if relation['type'] == "domain":
                        # if it's a domain, add it to the list.
                        domains.append(relation['indicator'])

        # return a list of strings of domains
        return domains
    # end GetDomainsFromResults()

    def GetIPsFromResults(self, result, related=False):
        """
        Pass this function results from an API search and it will return
        a list of IP addresses from your list of indicators.
        You may optionally include IP indicators identified as related
        indicators.
        This returns a list of IP addresses, one per line. Good for collecting
        all the IPs you want to feed into your firewall to block.
        """

        ips = []
        # loop through each JSON indicator
        for item in result:
            # pick ou the indicators that are IPs
            if item['type'] == "ip_address":
                # and add them to the list
                ips.append(item['indicator'])

            if related:
                # If you also wanted related indicators, loop through
                # those and check for IP addresses as well.
                for relation in item['relations']:
                    if relation['type'] == "ip_address":
                        # find the IPs and add them to the list.
                        ips.append(relation['indicator'])

        # return list of strings of IP addresses
        return ips
    # end GetIPsFromResults()

    def GetActorsFromResults(self, result):
        """
        Feed this function the results from an API search and it will return
        the name(s) of any threat actors associated with this list of indicators.
        If you already have some IPs, or domains, for example, you can use this to
        check for attribution.
        The function returns a raw list of actor names, you may want to dedupe them.
        """

        actors = []
        # loop through each JSON item in the results
        for item in result:
            # grab the actors section
            a = item['actors']
            if a:
                # if there's anything in here loop through them
                for x in a:
                    # add each actor the list we're building
                    actors.append(x)

        # return the list of actors that have been identified.
        # This list is raw, you may want to sort and dedupe.
        return actors
    # end GetActorsFromResults()


"""   REFERENCE
example = "actor?equal=ROCKETKITTEN"
example = "indicator?equal=www.we11point.com"
example = "actor?match=panda"
example = "actor?match=panda&sort=malicious_confidence&order=desc"
example = "last_updated?gte=1427846400&sort=last_updated&order=asc&perPage=100&page=1"
"""

# end class CSIntelAPI
######################################################################################

"""
This section sets up the module to use not as a class but called directly from the CLI
"""

if __name__ == "__main__":
    """
    This function sets up the API python file to be called directly. So this code
    can either be imported into another script or some functions can be called
    directly from the command line by running this script directly. This section
    never runs if this file was imported.

    To see how this file can be executed directly run it with "-h" to see the
    help on which command line flags are needed.

    The primary requirement is to feed this scrip your Customer ID and Key. This
    can be done through CLI arguments or by specificying a config file. See the
    documentation at the beginning (pydoc ./CSIntel.py)

    There are output options to select as well, with --out. The default, all, is to
    print all the json received. You can also select to print out all the
    indicators, which will show each prepended by the type of indicator.
    """
    import argparse
    import json
    import pprint

    # Let's set this up to parse setup config and other arguments from the CLI
    parser = argparse.ArgumentParser(description="CS Intel API - This program can be executed directly to work with CrowdStrike's Threat Intel API or be imported into other scripts to use.")
    parser.add_argument('--custid', type=str, help="API Customer ID", default=None)
    parser.add_argument('--custkey', type=str, help="API Customer Key", default=None)
    parser.add_argument('--perPage', '-p', type=str, help="How many indicators per page?", default="100")
    parser.add_argument('--Page', type=str, help="Page number of results to get.", default="1")
    parser.add_argument('--write', '-w', action='store_true', default=False, help='Write the API config to the file specified by the --config option')
    parser.add_argument('--config', '-c', type=str, help="Configuration File Name", default=defaultConfigFileName)
    parser.add_argument('--raw', action='store_true', default=False, help='Raw JSON, do not print pretty')
    parser.add_argument('--debug', '-b', action='store_true', default=False, help='Turn on some debug strings')

    # Error management is easier by specificying a group for the commands that can be used.
    # Each of these are actions/searches the script can take.
    cmdGroup = parser.add_mutually_exclusive_group(required=True)
    cmdGroup.add_argument('--actor', '-a', type=str, help="Search for an actor by name", default=None)
    cmdGroup.add_argument('--actors', '-s', type=str, help="Search for a actors by pattern", default=None)
    cmdGroup.add_argument('--ip', type=str, help="Search for an IP address", default=None)
    cmdGroup.add_argument('--domain', type=str, help="Search for a domain", default=None)
    cmdGroup.add_argument('--report', type=str, help="Search for a report name, e.g. CSIT-XXXX", default=None)
    cmdGroup.add_argument('--indicator', '-i', type=str, help="Search for an indicator", default=None)
    cmdGroup.add_argument('--label', '-l', type=str, help="Search for a label", default=None)
    cmdGroup.add_argument('--target', type=str, help="Search by Targeted Industry", default=None)
    cmdGroup.add_argument('--confidence', type=str, help="Search by Malicious Confidence", default=None)
    cmdGroup.add_argument('--killchain', type=str, help="Search by kill chain stage", default=None)
    cmdGroup.add_argument('--malware', type=str, help="Search by malware family", default=None)
    cmdGroup.add_argument('--active', action='store_true', help="Get confirmed active indicators", default=None)
    cmdGroup.add_argument('--threat', type=str, help="Search by threat type", default=None)
    cmdGroup.add_argument('--domaintype', type=str, help="Search by domain type", default=None)
    cmdGroup.add_argument('--iptype', type=str, help="Search by IP Type", default=None)
    cmdGroup.add_argument('--emailtype', type=str, help="Search by email address type", default=None)
    cmdGroup.add_argument('--day', action='store_true', help="Get all indicators that have changed in 24 hours", default=None)
    cmdGroup.add_argument('--week', action='store_true', help="Get all indicators that have changed in the past week", default=None)
    cmdGroup.add_argument('--download', '-f', type=str, help="Download a file by hash from Malquery", default=None)
    cmdGroup.add_argument('--downloadReport', '-R', type=str, help="Download a report, e.g. CSIT-XXXX", default=None)
    cmdGroup.add_argument('--downloadReportFiles', '-F', type=str, help="Download files associated with a report name, e.g. CSIT-XXXX", default=None)


    parser.add_argument('--out', '-o', choices=['all', 'indicators', 'hashes', 'domains', 'ips', 'actors', 'reports', 'IfReport'], help="What should I print? Default: all", default='all')
    parser.add_argument('--count', choices=['actors'], help="Tally count totals by variable stipulated here.", default=None)
    #TODO Mutually exclusive group ^^

    parser.add_argument('--related', action='store_true', help="Flag: Include related indicators.", default=False)
    parser.add_argument('--deleted', action='store_true', help="Include deleted indicators.", default=False)

    # run this and parse out the arguments
    args = parser.parse_args()

    # Some error checking on parsed configuration
    if args.write is True and args.config is None:
        raise Exception("To write to config file you must pass file name to --config")
    if (args.custid is None and args.custkey is not None) or (args.custkey is None and args.custid is not None):
        raise Exception("Must include both customer ID and key")

    # Now check to see if we're getting API settings from CLI or config file
    # if the write flag is set pass the config file name to be written to.
    if args.custid is not None:
        # use CLI parameters
        custid = args.custid
        custkey = args.custkey
    else:
        # no ID and key from argument, get them from config file
        (custid, custkey, perpage) = readConfig(args.config)

    # Create the API object
    api_obj = CSIntelAPI(custid, custkey, args.perPage, args.Page, args.deleted, args.debug)

    # Check to see if config in memory should be written to disk
    if args.write:
        api_obj.writeConfig(args.config)

    # now do stuff...

    if args.actors is not None:         # search actors for a pattern
        result = api_obj.SearchActorMatch(args.actors, sort='actor')

    if args.actor is not None:          # search actors for a specific actor
        result = api_obj.SearchActorEqual(args.actor, sort="malicious_confidence", order='desc')

    if args.ip is not None:             # search API for an IP address
        result = api_obj.SearchIP(args.ip)

    if args.domain is not None:         # search API for a domain
        result = api_obj.SearchDomain(args.domain)

    if args.report is not None:         # search API for a report name
        result = api_obj.SearchReport(args.report)

    if args.indicator is not None:      # generic indicator search
        result = api_obj.SearchIndicatorMatch(args.indicator)

    if args.label is not None:          # generic label search
        result = api_obj.SearchLabel(args.label)

    if args.target is not None:         # search targeted industry
        result = api_obj.SearchTarget(args.target)

    if args.confidence is not None:     # search malicious confidence
        result = api_obj.SearchConfidence(args.confidence)

    if args.killchain is not None:      # search by kill chain stage
        result = api_obj.SearchKillChain(args.killchain)

    if args.malware is not None:        # search by malware family
        result = api_obj.SearchMalware(args.malware)

    if args.active is not None:         # search for confirmed active malware
        print("WTF LOL")
        result = api_obj.SearchActive()

    if args.threat is not None:         # search by threat type
        result = api_obj.SearchThreatType(args.threat)

    if args.domaintype is not None:     # search by domain type
        result = api_obj.SearchDomainType(args.domaintype)

    if args.iptype is not None:         # search by IP Address type
        result = api_obj.SearchIPType(args.iptype)

    if args.emailtype is not None:      # search by email type
        result = api_obj.SearchEmailType(args.emailtype)

    if args.day is not None:            # grab indicators for the last day
        result = api_obj.SearchLastDay()

    if args.week is not None:           # grab indicators for the last week
        result = api_obj.SearchLastWeek()

    if args.download is not None:       # try to download file from MQ
        result = api_obj.MQDownloadHash(args.download)
        #print(result.headers.get('content-type')) #debug
        filename = args.download    #name file the hash
        open(filename, 'wb').write(result.content)
        #exit
        raise SystemExit


    if args.downloadReport is not None:
        result = api_obj.GetReportPDF(args.downloadReport)
        filename = args.downloadReport + ".pdf"
        open(filename, 'wb').write(result.content)
        raise SystemExit


    if args.downloadReportFiles is not None:
        
        result = api_obj.SearchReport(args.downloadReportFiles)
        data = json.loads(result.text)
        hashes = api_obj.GetHashesFromResults(data, related=args.related)

        for h in hashes:
            result = api_obj.MQDownloadHash(h)
            filename = h
            open(filename, 'wb').write(result.content)
            
        raise SystemExit



    # load the raw JSON into python friendly structure
    print(result.text)
    data = json.loads(result.text)

    # print results
    if args.out == "hashes":
        # get hashes form results, pass related option
        hashes = api_obj.GetHashesFromResults(data, related=args.related)
        for h in hashes:
            print(h)
    elif args.out == "indicators":
        # get all the indicators
        indicators = api_obj.GetIndicatorsFromResults(data, related=args.related)
        # dedupe indicators
        uniqueIndicators = set(indicators)
        # print them one per line
        for i in uniqueIndicators:
            print(i)
    elif args.out == "reports":
        # print any report names associated with these indicators
        reports = api_obj.GetReportsFromResults(data)
        reports.sort()  # sort list
        for r in reports:
            # print one per line
            print(r)
    elif args.out == "domains":
        # get the domains from our results
        domains = api_obj.GetDomainsFromResults(data, related=args.related)
        domains.sort()  # sort list
        # print one per line
        for d in domains:
            print(d)
    elif args.out == "actors":
        # print what actors are tied to these indicators
        actors = api_obj.GetActorsFromResults(data)
        # dedupe the list
        uniqueActors = set(actors)
        for a in uniqueActors:
            # print one per line
            print(a)
    elif args.out == "ips":
        # get the IP addresses from our list of indicators
        ips = api_obj.GetIPsFromResults(data, related=args.related)
        uniqueIps = set(ips)  # dedupe list
        for i in uniqueIps:
            # print one per line
            print(i)
    elif args.out == "IfReport":
        # print out the raw data, but only if there is an associated
        # report with it.
        for datum in data:
            if len(datum['reports']) > 0:
                print(datum)
    elif args.count == "actors":
        from collections import Counter
        actorSet = []
        
        for datum in data:
            if len(datum['actors']) > 0:
                actorSet.extend( datum['actors'] )
            else:
                actorSet.append( 'None' )

        cActors = Counter(actorSet)

        for key, value in cActors.items():
            print(key, ",", value)


    else:
        # by default pretty print the whole JSON
        if args.raw is False:
            pprint.pprint(data)
        else:
            print(data)

# EOF
