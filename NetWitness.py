#!/usr/bin/env python
#pylint: disable=C0103
######################
#
# NetWitness.py
#
# driver to automatically query the Netwitness system and
# parse the results.
#
# requires pytz and IPy, which are not in the standard python library
#
# Copyright (c) 2015 United States Government/National Institutes of Health
# Author: Aaron Gee-Clough
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#
#####################

import requests
from requests import auth
import datetime
import types
import pytz
import StringIO
import IPy
import re

typeMappings = {
                "alias.host": "hostname",
                'alias.ip': 'ip',
                'alias.ipv6': "ipv6",
                "ip.src": "srcIP",
                "ip.dst": "dstIP",
                'ip.proto': "proto",
                'ip6.src': 'srcIP6',
                'ip6.dst': 'dstIP6',
                'ip6.proto': 'protov6',
                'udp.dstport': 'udpport',
                'tcp.dstport': 'tcpport'}

validFields = [
               'alias.host',
               'alias.ip',
               'alias.ipv6',
               'attachment',
               'email',
               'filename',
               'ip.dst',
               'ip.proto',
               'ip.src',
               'ipv6.dst',
               'ipv6.proto',
               'ipv6.src',
               'service',
               'sessionid',
               'size',
               'subject',
               'time',
               'tcp.dstport',
               'udp.dstport',
               ]


def isValidHostname(hostname):
    # thank you Tim Pietzcker:
    # http://stackoverflow.com/questions/2532053/validate-hostname-
    #string-in-python/2534561
    #
    if len(hostname) > 255:
        return False
    if hostname[-1:] == ".":
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def isValidSearchField(searchList):
    response = True
    for entry in searchList:
        if entry not in validFields:
            response = False
    return response


class Netwitness(object):
    """
    Netwitness(IP, port, user, pw, ssl=False, timeZone=US/Eastern
    Class to query Netwitness for certain data.

    Requires a username & PW that has access to the Netwitness API.

    Requires a time zone recognized by pytz to be defined because Netwitness
    parses all submitted times as UTC. (But, stupidly, returns times in the
    local timezone of the server. This is very broken behavior.)

    """
    def __init__(self, targetIP,
                 targetPort,
                 user,
                 pw,
                 ssl=False,
                 timeZone="US/Eastern",
                 maxSessions=500,
                 timeout=120):
        try:
            IPy.IP(targetIP)
        except:
            raise Exception("not a good Netwitness server IP %s" % targetIP)
        try:
            int(targetPort)
        except:
            raise Exception("not a good port %s" % targetPort)
        if ssl is not True and ssl is not False:
            raise Exception("ssl must be True or False")
        if ssl:
            self.baseURL = "https://%s:%s" % (targetIP, targetPort)
        else:
            self.baseURL = "http://%s:%s" % (targetIP, targetPort)
        self.timeZone = timeZone
        try:
            self.maxSessions = int(maxSessions)
        except:
            raise Exception("max sessions must be integer")
        try:
            self.timeout = int(timeout)
        except:
            raise Exception("timeout must be integer")
        self.parameters = None
        self.basicauth = None
        self._setup(user, pw)
        self._login()

    def _makeJsonRequest(self, targetURL):
        """_makeJsonrequest(self, targetURL)
        Actually make the request to the system. requires a URL to be
        already constructed.

        Will return the json-loaded response, or None if the request
        fails/times out.
        """
        headers = {"Accept":"application/json"}

        try:
            query = requests.get(targetURL, headers=headers, timeout=self.timeout, auth=self.basicauth, verify=False)
        except requests.exceptions.HTTPError:
            # this means the request has likely timed out.
            query = None
        except:
            # this means the server didn't respond with valid HTTP response
            query = None
        if query:
            try:
                response = query.json()
            except ValueError:
                # there likely was no Json to decode.
                response = None
        else:
            response = None
        return response

    def _parseResponse(self, response):
        """
        _parseResponse(self, response)

        Parse the JSON from a response to get just the NetWitness response.
        If given a response of None, returns None also.
        otherwise returns a list, each list entry being a dictionary containing
        the field names and their corresponding data

        Performs some transforms to the response data also, to make it easier
        to parse (and to allow things like Django to correctly access the
        dictionary items...django doesn't handle "." in dictionary keys well).
        """
        if response is None:
            return None
        if not type(response) == types.DictionaryType:
            raise Exception("not a real response or error: %s" % str(response))
        if not "results" in response:
            raise Exception("no results")
        entries = {}
        for entry in response['results']['fields']:
            groupID = entry['group']
            if groupID not in entries:
                entries[groupID] = {}
            # remove the '.'s for some systems, like django, that
            # can't handle getting .'s in variable names
            if entry['type'] in typeMappings:
                responsetype = typeMappings[entry['type']]
            else:
                responsetype = entry['type']
            if responsetype not in entries[groupID]:
                entries[groupID][responsetype] = [entry['value']]
            else:
                entries[groupID][responsetype].append(entry['value'])
        # the intent here: send back a sorted list of entries, sorted by the
        # groupID, which should loosely correspond to the time of the session
        sendBack = []
        keys = entries.keys()
        keys.sort()
        for key in keys:
            sendBack.append(entries[key])
        for counter in range(len(sendBack)):
            for key in sendBack[counter].keys():
                if key == "time":
                    fullTime = ""
                    for time in sendBack[counter]['time']:
                        fullTime = fullTime +\
                            datetime.datetime.fromtimestamp(time).strftime(
                                                    "%Y-%m-%d&nbsp;%H:%M:%S")
                    sendBack[counter]['time'] = fullTime
                elif type(sendBack[counter][key]) == types.ListType:
                    # first, remove duplicates, then join the results
                    dedupedlist = list(set(sendBack[counter][key]))
                    sendBack[counter][key] = ", ".join(dedupedlist)
        return sendBack

    def _setupTimes(self, timeFrame):
        """
        _setupTimes(timeFrame)

        Takes a string ('today', 'yesterday', '24' or '48') and translates
        those into utc datetime objects for use in querying netwitness.
        returns (startTime, endTime), both datetime objects.

        """
        if timeFrame == "today":
            start = datetime.datetime.now()
            start = start.replace(hour=0).replace(minute=0).replace(second=0)
            end = datetime.datetime.now()
        elif timeFrame == "yesterday":
            end = datetime.datetime.now()
            end = end.replace(hour=0).replace(minute=0).replace(second=0)
            start = end - datetime.timedelta(hours=24)
        elif timeFrame == "24":
            end = datetime.datetime.now()
            start = end - datetime.timedelta(hours=24)
        elif timeFrame == "48":
            end = datetime.datetime.now()
            start = end - datetime.timedelta(hours=48)
        else:
            raise Exception("bad time submitted: %s" % timeFrame)
        (start, end) = self._translateTimesToUTC(start, end)
        return (start, end)

    def _translateTimesToUTC(self, startTime, endTime):
        """
        _translateTimesToUTC(startTime, endTime)

        takes two datetime.datetime objects and translates them to UTC,
        depending on the self.timeZone value
        """
        if not self._validateTimes(startTime, endTime):
            return False
        # fix stupid timezone stuff.
        here = pytz.timezone(self.timeZone)
        try:
            starthere = here.localize(startTime)
        except ValueError:
            #you'll get a value error if startTime already got a timezone set
            # this didn't use to be the case, but is apparently now.
            starthere = startTime
        start = starthere.astimezone(pytz.utc)
        try:
            endhere = here.localize(endTime)
        except ValueError:
            # same above
            endhere = endTime
        end = endhere.astimezone(pytz.utc)
        return (start, end)

    def _validateTimes(self, start, end):
        isValid = True
        if not isinstance(start, datetime.datetime):
            isValid = False
        if not isinstance(end, datetime.datetime):
            isValid = False
        if not isValid:
            return False
        if start > end:
            isValid = False
        if end - start > datetime.timedelta(hours=48):
            isValid = False
        return isValid

    def _buildURL(self,
                  selects,
                  wheres,
                  times,
                  expiry=None,
                  size=None):
        """
_buildURL(selects, wheres, times, expiry=self.timeout, size=self.maxSessions)

        Build the actual URL for a Netwitness API query, including setting the
        timeout (expiry in Netwitness terms) for a query (default 120 seconds)
        and the maximum number of responses (500 by default).

        selects = which Netwitness data values to select. expects a list
        wheres = clauses to search on. dict of key:value => where key=value
        times = start and end times, as built by _setupTimes (or manually,
            if you know what you're doing)

        returns the full url for the query as a string
        """
        if expiry is None:
            expiry = self.timeout
        else:
            try:
                int(expiry)
            except:
                expiry = self.timeout
        if size is None:
            size = self.maxSessions
        else:
            try:
                int(size)
            except:
                size = self.maxSessions
        if ((type(times) != types.ListType) and
                (type(times) != types.TupleType)) or (len(times) != 2):
            raise Exception("bad times submitted.")
        if not isValidSearchField(selects):
            raise Exception("not a valid field to query")
        testTime = datetime.datetime.now()
        for timeentry in times:
            if type(timeentry) != type(testTime):
                raise Exception("time submitted not a datetime")
        # expects fields to be a dictionary
        # I know this isn't according to pep8
        urlList = []
        urlList.extend((self.baseURL,
                        "/sdk?expiry=",
                        str(expiry),
                        "&size=",
                        str(size),
                        "&id1=%s&id2=%s" % (self.parameters['field1'],
                                           self.parameters['field2']),
                        "&msg=query&query=select+"
                        ))
        urlList.append(",".join(selects))
        urlList.append("+where+")
        for key in wheres:
            urlList.append(key + "%3d%27" + wheres[key] + "%27+%26%26")
        urlList.extend(("+time%3d%27",
                       times[0].strftime("%Y-%m-%d %H:%M:%S").replace(" ",
                                                                       "%20"),
                       "%27-%27",
                       times[1].strftime("%Y-%m-%d %H:%M:%S").replace(" ",
                                                                       "%20"),
                       "%27"
                       ))
        url = ''.join(urlList)
        return url

    def _buildPcapURL(self, sessionid):
        """
        _buildPcapURL(sessionid)

        returns the url necessary to download the pcap of a given session id.
        sessionID is expected to be a string of a single int, a single int,
        a list of ints, or a comma-separated list of ints.
        """
        if type(sessionid) is str:
            if "," in sessionid:
                sessionIDs = sessionid.split(",")
            else:
                sessionIDs = [sessionid]
        elif type(sessionid) is list:
            sessionIDs = sessionid
        else:
            raise Exception("Bad sessionid submitted: %s" % sessionid)
        try:
            for session in sessionIDs:
                int(session)
        except ValueError:
            raise Exception("bad sessionid submitted")
        url = ''.join([self.baseURL,
                      "/sdk/content?session=",
                      ",".join([str(ID) for ID in sessionIDs]),
                      "&render=pcap"])
        return url

    def _buildFileURL(self, sessionid):
        """
        _buildFileURL(sessionid)

        returns the URL necessary to download the files from a given sessionid
        sessionID is expected to be a string or single int.
        """
        try:
            sessionid = int(sessionid)
        except ValueError:
            raise Exception("bad sessionID submitted: %s" % sessionid)
        url = ''.join([self.baseURL,
                       '/sdk/content?session=',
                       str(sessionid),
                       "&render=files&base64=1"])
        return url

    def _setup(self, user, pw):
        """
        _setup(user, pw)

        handle the initial setup, including the http password handler
        installation and the url opener creation. Does not actually log in

        """
        basic = auth.HTTPBasicAuth(user, pw)
        self.basicauth = basic

    def _login(self):
        """
        _login()

        based on the data from _setup(), logs into Netwitness, and gets the
        login parameters (session ranges,etc) that netwitness expects to be
        included in each search.
        """
        loginPath = "/sdk?msg=session&id1=0&id2=0"
        loginURL = self.baseURL + loginPath
        response = self._makeJsonRequest(loginURL)
        if not response:
            raise Exception("failed login")
        if not "params" in response:
            raise Exception("failed login")
        self.parameters = response['params']

    def downloadPcap(self, sessionid):
        """
        downloadPcap(sessionid)

        downloads the pcap of a given sessionid or list of sessionIDs.
        Returns a StringIO file containing the pcap.

        """
        sessionIDs = []
        if type(sessionid) is int:
            sessionIDs = [sessionid]
        elif type(sessionid) is list:
            problem = False
            for id in sessionid:
                try:
                    sessionIDs.append(int(id))
                except ValueError:
                    problem = True
            if problem:
                raise Exception("bad sessionID in given list: %s" % sessionid)
        elif (type(sessionid) is str) or (type(sessionid) is unicode):
            if "," in sessionid:
                problem = False
                for id in sessionid.split(","):
                    try:
                        sessionIDs.append(int(id))
                    except ValueError:
                        problem = True
                if problem:
                    raise Exception(
                            "bad sessionID in given list: %s " % sessionid
                            )
            else:
                try:
                    int(sessionid)
                    sessionIDs = [sessionid]
                except ValueError:
                    raise Exception("bad sessionID submitted %s" % sessionid)
        if not sessionid:
            return None
        if not sessionIDs:
            return None
        url = self._buildPcapURL(sessionIDs)
        query = requests.get(url, auth=self.basicauth, timeout=self.timeout, verify=False)
        returnFile = StringIO.StringIO('wb')
        for block in query.iter_content(1024):
            if not block:
                break
            returnFile.write(block)
        returnFile.seek(0)
        return returnFile

    def downloadFile(self, sessionid):
        """
        downloadFile(sessionid)

        returns the file for a given sessionID. Can only be called for
        one sessionID at a time.
        """
        try:
            sessionid = int(sessionid)
        except ValueError:
            raise Exception("bad sessionID submitted: %s " % sessionid)
        if not sessionid:
            return None
        url = self._buildFileURL(sessionid)
        query = requests.get(url, auth=self.basicauth, timeout=self.timeout, verify=False)
        returnFile = StringIO.StringIO('wb')
        for block in query.iter_content(1024):
            if not block:
                break
            returnFile.write(block)
        returnFile.seek(0)
        return returnFile

    def getSessionsForIP(self,
                                sourceIP=None,
                                destIP=None,
                                startTime=None,
                                endTime=None,
                                timeFrame="today",
                                searches=('sessionid',
                                        'time',
                                        'ip.src',
                                        'ip.dst',
                                        'alias.host',
                                        'tcp.dstport',
                                        'udp.dstport',
                                        'filename',
                                        'size')):
        """
        getSessionsForIP(sourceIP=None, destIP=None, startTime=None,
                            endTime=None, timeFrame="today",
                                searches=['sessionid', 'time', 'ip.src',
                                        'ip.dst', 'alias.host', 'tcp.dstport',
                                        'udp.dstport', 'filename', 'size']
        get all sessions for a given IP or set of IPs.

        startTime is a  datetime object for when to start the search
        endTime is a datetime object for when to end the search.
        timeFrame is a string defines as per _setupTimes

        if startTime and endTime are defined, timeFrame will be ignored.

        searches are the fields to be returned in the query

        returns results as per _parseResponse
        """
        queryDict = {}
        if not sourceIP and not destIP:
            raise Exception("need to provide at least a source or dest")
        # verify that the IPs are correctly formed IPs. I don't really
        # care about the IPy objects, just using their validation.
        if sourceIP:
            try:
                IPy.IP(sourceIP)
                queryDict['ip.src'] = sourceIP
            except:
                raise Exception("bad Ip address submitted %s" % sourceIP)
        if destIP:
            try:
                IPy.IP(destIP)
                queryDict['ip.dst'] = destIP
            except:
                raise Exception("Bad IP address submitted: %s" % destIP)
        if not isValidSearchField(searches):
            raise Exception("bad list of fields to search on")
        if (startTime is not None and endTime is not None):
            times = self._translateTimesToUTC(startTime, endTime)
        else:
            times = self._setupTimes(timeFrame)
        queryURL = self._buildURL(searches,
                                 queryDict,
                                  times)
        response = self._makeJsonRequest(queryURL)
        return self._parseResponse(response)

    def getSessionsForHost(self,
                        host,
                        startTime=None,
                        endTime=None,
                        timeFrame="today",
                        searches=('sessionid',
                                   'time',
                                   'ip.src',
                                   'ip.dst',
                                   'tcp.dstport',
                                   'udp.dstport',
                                   'filename',
                                   'size')
                        ):
        """
        getSessionsForHost(Host,
                            startTime=None,
                            endTime=None
                            timeFrame="today",
                            searches=['sessionid', 'time', 'ip.src', 'ip.dst',
                                        'tcp.dstport', 'udp.dstport',
                                        'filename','size'])

        get all sessions that are going to a particular destination hostname.

        startTime and endTime are datetime objects that define when the search
        should begin and end. if startTime and endTime are defined, timeFrame
        is ignored.

        timeFrame is a string per _setupTimes
        searches is the fields to be returned in the query.
                default: sessionid, time, ip.src, ip.dst, tcp.dstport,
                        udp.dstport, filename, and size

        returns results as per _parseResponse
        """
        if not isValidHostname(host):
            raise Exception("bad hostname submitted: %s" % host)
        if not isValidSearchField(searches):
            raise Exception("bad list of fields to search on")
        if (startTime and endTime):
            times = self._translateTimesToUTC(startTime, endTime)
        else:
            times = self._setupTimes(timeFrame)
        queryURL = self._buildURL(searches, {'alias.host': host}, times)
        response = self._makeJsonRequest(queryURL)
        return self._parseResponse(response)

    def getSessionsForEmail(self,
                  subject=None,
                  email=None,
                  startTime=None,
                  endTime=None,
                  timeFrame="today",
                  searches=('sessionid',
                            'time',
                            'email',
                            'subject',
                            'attachment',
                            'size')
                  ):
        """
        getSessionsForEmail(subject=None,
                            email=None,
                            startTime=None,
                            endTime=None,
                            timeFrame="today",
                            searches = ['sessionid',
                                        'time',
                                        'email',
                                        'subject',
                                        'filename',
                                        'size'])

        get all email sessions involving a given email address or subject.
        One of "subject" or "email" address must be provided,
        but you do not need to supply both.

        startTime and endTime are datetime objects that define when a
        search should start and end. If startTime and endTime are defined,
        timeFrame is ignored.

        timeFrame a string per _setupTimes
        searches is the fields to be returned in the query. default: sessionid,
                time, email addresses, email subject, attachment filename,
                and size

        returns results as per _parseResponse
        """
        if not (subject or email):
            raise Exception("I need to search for something")
        if not isValidSearchField(searches):
            raise Exception("bad list of fields to search on")
        if (startTime and endTime):
            times = self._translateTimesToUTC(startTime, endTime)
        else:
            times = self._setupTimes(timeFrame)
        queryDict = {'service': "25"}
        if subject:
            queryDict['subject'] = subject
        if email:
            queryDict['email'] = email.replace("@", "%40")
        queryURL = self._buildURL(searches, queryDict, times)
        response = self._makeJsonRequest(queryURL)
        return self._parseResponse(response)


if __name__ == "__main__":
    pass
