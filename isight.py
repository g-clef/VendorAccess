#!/usr/bin/env python
# pylint: disable=C0103
# pylint: disable=E1101


#######################
#
# iSight query library
#
# requires: requests
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
import hmac
import hashlib
import email.Utils
import urllib


content_types = {"JSON": "application/json",
                 "XML": "text/xml",
                 "HTML": "text/html",
                 "PDF": "application/pdf",
                 "STIX": "application/stix",
                 "CSV": "text/csv",
                 "Snort": "application/snort",
                 "Zip": "application/zip"
                 }

allowed_report_list_types = ["JSON",
                             "XML"
                             ]

allowed_report_types = ["JSON",
                        "XML",
                        "HTML",
                        "PDF",
                        "STIX"
                        ]

allowed_publication_types = ["threat",
                             "malware",
                             "vulnerability"
                             ]

allowed_detail_levels = ['full',
                         'summary',
                         'title']


class iSightServer(object):
    def __init__(self, baseURL, key, secret):
        self.baseURL = baseURL
        self.key = key
        self.secret = secret
        self.session = None

    def _makeHeaders(self, query, content_type, version="2.0"):
        headers = {"Accept": content_types[content_type],
                   "Accept-Version": version,
                   "X-Auth": self.key,
                   "X-App-Name": "mysight-api",
                   #"Content-Type": content_types[content_type]
                   }
        timestamp = email.Utils.formatdate(localtime=True)
        headers['Date'] = timestamp
        hashedVal = query + version + content_types[content_type] + timestamp
        newHash = hmac.new(self.secret, hashedVal, hashlib.sha256)
        headers['X-Auth-Hash'] = newHash.hexdigest()
        return headers

    def _getURL(self, url, content_type):
        if not self.session:
            self.session = requests.Session()
        headers = self._makeHeaders(url, content_type)
        response = self.session.get(self.baseURL + url, headers=headers)
        if content_type == "JSON":
            return response.json()
        else:
            return response.content

    def getReportList(self, sinceEpoch=None, sinceID=None, sinceIDVersion=None,
                      threatScape=None, publicationType=None, limit=None,
                      startDate=None, endDate=None, content_type="JSON"):
        """Get the list of available reports from iSight. Arguments:

sinceEpoch: <optional> specify this to limit results to only reports after
            this time. Expects an integer as Epoch time. iSight asks
            that you limit this to no more than 90 days in the past.
            If left out, will default to 24 hours.

sinceID: <optional> Specify a report ID as the first report. If this is
        Specified, you can't use sinceEpoch

sinceIDVersion: <optional> Specify the version of a report to start
                 the list from. This can only be used in conjunction
                 with sinceID.

threatScape: <optional> comma-delimited list of which iSight ThreatScape
            products will be included in the reports. Defaults to all.

publicationType: <optional> comma separated list of which publication
                types should be included in the list of reports.
                valid entries are "threat", "malware" or "vulnerability".
                Defaults to all.

limit: <optional>Limit the number of report IDs to return. Default is 1000

startDate: <optional>epoch Timestamp to limit reports to only ones after this
            time. Functionally similar to sinceEpoch, but can be paired with
            endDate.

endDate: <optional> epoch timestmap to limit reports to only ones before
        this time. Can only be used with startDate, not sinceEpoch.

content_type: <optional> Which content type of report to return. Defaults
                to JSON.
        """
        url = "/report/index"
        if content_type not in allowed_report_list_types:
            raise Exception("Bad content_type")
        arguments = {}
        if sinceEpoch:
            arguments['since'] = int(sinceEpoch)
        if sinceID:
            if sinceEpoch:
                raise Exception("cannot use both 'sinceEpoch' and 'sinceID' arguments together. Pick one.")
            arguments['sinceReport'] = sinceID
        if sinceIDVersion:
            if not sinceID:
                raise Exception("cannotuse sinceIDVersion without sinceID")
            arguments['sinceReportVersion'] = sinceIDVersion
        if threatScape:
            arguments['threatScape'] = threatScape
        if publicationType:
            publications = publicationType.split(",")
            for pub in publications:
                if pub not in allowed_publication_types:
                    raise Exception("publicationType values must be in %s" % allowed_publication_types)
            arguments['pubType'] = publicationType
        if limit:
            arguments['limit'] = limit
        if startDate:
            arguments['startDate'] = startDate
        if endDate:
            if not startDate:
                raise Exception("endDate must be used with startDate")
            arguments['endDate'] = endDate
        if arguments:
            urlArgs = urllib.urlencode(arguments)
            url += "?" + urlArgs
        return self._getURL(url, content_type)

    def getReport(self, reportID, detail=None, noTags=None, content_type="JSON"):
        """
        Get a specific report. Arguments:
reportID: <required> the ID of the report to collect.

detail: <optional> The level of detail for the report. Valid levels are "full",
        "summary", "title". Default is the max level  you are entitled to
        through their permissions.

noTags: <optional> Set to True to remove Tags section from the report.

content_type: <optional> what format to return the report in. Default is
            "JSON"
        """
        url = "/report/%s" % reportID
        urlArgs = ""
        if detail or noTags:
            if detail:
                if detail not in allowed_detail_levels:
                    raise Exception("detail must be in %s" % allowed_detail_levels)
                urlArgs += "detail=%s" % detail
            if noTags:
                if len(urlArgs > 1):
                    urlArgs += "&noTags"
                else:
                    urlArgs += "noTags"
        if urlArgs:
            url += "?" + urlArgs
        return self._getURL(url, content_type)
