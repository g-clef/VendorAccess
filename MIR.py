#!/usr/bin/env python
# pylint: disable=C0103
# pylint: disable=E1101
#
#######################
#
# MIR API library
#
# requires: requests and lxml libraries that aren't in the python
#           standard library
#
# applies to MIR 2.5 (controller version 2.3.15)
#    Will update for MIR 3.0/HX in the future.
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


import lxml.etree
from urllib import quote_plus
import HTMLParser
import requests
import cStringIO


class MIR(object):
    def __init__(self, controller,
                 username=None,
                 password=None,
                 timeout=120,
                 debug=False):
        # the controller entry needs to not end with "/", so that all the URLs
        # can be absolute and not lead to 404's from double //'s in places they
        # don't belong.
        while controller.endswith("/"):
            controller = controller.strip("/")
        self.controller = controller
        self.username = username
        self.password = password
        self.debug = debug
        self.timeout = timeout
        self.lastTestofConnect = None
        self.connected = False

    def _getXMLfromURL(self, url):
        response = requests.get(url,
                                auth=(self.username, self.password),
                                verify=False)
        testIO = cStringIO.StringIO()
        for chunk in response.iter_content(1024):
            testIO.write(chunk)
        testIO.seek(0)
        tree = lxml.etree.parse(testIO)
        root = tree.getroot()
        return root

    def _fixNsmap(self, nsmap):
        # xpath doesn't support None as a valid type,and for some reason
        # the atom namespace is being grabbed as None in the nsmap by
        # lxml
        newMap = nsmap
        newMap['atom'] = newMap[None]
        newMap.pop(None)
        return newMap

    def _walkEntryList(self, root, nsmap):
        returnList = []
        entries = root.xpath("/atom:feed/atom:entry",
                             namespaces=nsmap,
                             smart_strings=False)
        for entry in entries:
            obj = {}
            fields = entry.xpath("mir:fields",
                                 namespaces=nsmap, 
                                 smart_strings=False)
            for field in fields:
                children = field.getchildren()
                for child in children:
                    obj[child.attrib['name']] = child.attrib['value']
                    child.clear()
            entry.clear()
            returnList.append(obj)
        del(entries)
        return returnList

    def getAllLabels(self):
        testUrl = self.controller + "/workspaces/1/attributes/all/"
        root = self._getXMLfromURL(testUrl)
        nsmap = self._fixNsmap(root.nsmap)
        labelList = self._walkEntryList(root, nsmap)
        root.clear()
        return labelList

    def getAllHosts(self):
        """
        return a list of all hosts defined.
        """
        url = self.controller + "/workspaces/1/hosts/all/"
        root = self._getXMLfromURL(url)
        nsmap = self._fixNsmap(root.nsmap)
        hosts = self._walkEntryList(root, nsmap)
        root.clear()
        return hosts

    def getHostsByLabel(self, labelID):
        """
        """
        try:
            int(labelID)
        except:
            return False
        testUrl = self.controller + \
                  "/workspaces/1/attributes/all/" + \
                  str(labelID) + "/resources/"
        root = self._getXMLfromURL(testUrl)
        nsmap = self._fixNsmap(root.nsmap)
        deviceList = self._walkEntryList(root, nsmap)
        root.clear()
        return deviceList

    def getAllScripts(self):
        """
        Return a list of all scripts.

        """
        url = self.controller +\
              "/workspaces/1/documents/all/" +\
              '?filter=content_type,=,"application/vnd.mandiant.script' +\
              '%2bxml"&title=Scripts'
        root = self._getXMLfromURL(url)
        nsmap = self._fixNsmap(root.nsmap)
        scripts = self._walkEntryList(root, nsmap)
        root.clear()
        return scripts

    def getNumHostsForAllLabels(self, labelList=None):
        """
        returns all hosts per label, in format:
            (LabelObj, NumberHosts)

        if labelList is provided, loops through those as if they
        are django objects, skips looking up all the labels first.

        """
        if labelList is None:
            labels = self.getAllLabels()
            numbers = []
            for label in labels:
                numHosts = self.getNumHostsByLabel(label.id)
                numbers.append((label, numHosts),)
        else:
            numbers = []
            for label in labelList:
                numHosts = self.getNumHostsByLabel(label.labelid)
                numbers.append((label, numHosts),)
        return numbers

    def getAllIoCs(self):
        """
        Intended to get a list of all IoCs, and return a list
        of IoC objects.

        Note: Mandiant lists all the IOC data in their "all" feed,
        but does it with escaped XML inside an XML attribute.

        For the record, that is truly nasty.
        """
        url = self.controller + "/workspaces/1/indicators/all/"
        root = self._getXMLfromURL(url)
        nsmap = self._fixNsmap(root.nsmap)
        iocs = self._walkEntryList(root, nsmap)
        fixedIocs = []
        parser = HTMLParser.HTMLParser()
        for ioc in iocs:
            ioc['ioc'] = parser.unescape(ioc['ioc'])
            fixedIocs.append(ioc)
        root.clear()
        return fixedIocs

    def getNumHostsByLabel(self, labelID):
        """
        """
        try:
            int(labelID)
        except:
            if self.debug:
                print "failed to cast labelID to integer"
            return False
        testUrl = self.controller + "/workspaces/1/attributes/all/" + \
                                    str(labelID) + "/"
        root = self._getXMLfromURL(testUrl)
        resourceCount = root.find("resources")
        if resourceCount is None:
            if self.debug:
                print "no resourceCount found in XML response"
            return False
        count = resourceCount.get("count")
        try:
            count = int(count)
        except:
            if self.debug:
                print "failed to cast resouceCount to integer"
            return False
        root.clear()
        return count

    def testScriptExists(self, scriptName):
        """Tests for whether or not a script exists on a controller.
        """
        testUrl = self.controller + \
                  '/workspaces/1/documents/all/?offset=0&max=1&' + \
                  'filter=content_type,=,"application/vnd.mandiant.' + \
                  'script%2bxml"&filter=title,=,"' + \
                  quote_plus(scriptName, safe='') + '"'
        root = self._getXMLfromURL(testUrl)
        nsmap = self._fixNsmap(root.nsmap)
        entries = root.xpath("/atom:feed/atom:link",
                             namespaces=nsmap,
                             smart_strings=False)
        root.clear()
        if len(entries) > 0:
            entries.clear()
            return True
        else:
            entries.clear()
            return False

    def getScriptURIbyName(self, scriptName):
        """
        """
        testUrl = self.controller + \
                  '/workspaces/1/documents/all/?offset=0&max=1' + \
                  '&filter=content_type,=,"application/vnd.mandiant.' + \
                  'script%2bxml"&filter=title,=,"' + \
                  quote_plus(scriptName, safe='') + '"'
        root = self._getXMLfromURL(testUrl)
        nsmap = self._fixNsmap(root.nsmap)
        entries = root.xpath("/atom:feed/atom:link",
                             namespaces=nsmap,
                             smart_strings=False)
        if not entries:
            return False
        scriptLink = entries[0].attrib['href']
        entries.clear()
        root.clear()
        return self.controller + scriptLink

    def getHostHash(self, host):
        """
        """
        url = self.controller + "/apps/webclient/hosts/search?q=" + host
        if self.debug:
            print "getting host hash for host: %s" % host
            print url
        response = requests.get(url,
                                auth=(self.username, self.password),
                                verify=False)
        result = response.json()
        # dont' like this. must do better
        hashval = None
        count = 0
        if not result:
            if self.debug:
                print "host not found."
            return None
        for entry in result:
            if count <= 1:
                hashval = entry['am_cert_hash']
            else:
                hashval = None
            count += 1
        return hashval
