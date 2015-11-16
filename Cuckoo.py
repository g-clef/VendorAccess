#!/usr/bin/env python
# pylint: disable=C0103
# pylint: disable=E1101

############################
#
# Cuckoo.py
#
# submit and look stuff up in a Cuckoo server
#
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
##########################

import requests
from HTMLParser import HTMLParser
from xml.etree import ElementTree as etree
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
import re
from celery.utils.log import get_task_logger
import copy
import json

logger = get_task_logger(__name__)


class BodyParser(HTMLParser):
    def __init__(self, startTag=""):
        HTMLParser.__init__(self)
        self.tree = etree.TreeBuilder()
        if not startTag:
            self.started = True
        else:
            self.started = False
        self.startTag = startTag

    def handle_starttag(self, tag, attrs):
        if (not self.started and tag == self.startTag) or self.started:
            self.started = True
            self.tree.start(tag, dict(attrs))

    def handle_endtag(self, tag):
        if self.started:
            self.tree.end(tag)
        if tag == self.startTag:
            self.started = False

    def handle_data(self, data):
        if self.started:
            self.tree.data(data)

    def close(self):
        HTMLParser.close(self)
        return self.tree.close()


def validateURL(url):
    valid = True
    validator = URLValidator()
    try:
        validator(url)
    except ValidationError:
        valid = False
    return valid


class Cuckoo(object):
    def __init__(self, baseURL, machines):
        if type(baseURL) not in (str, unicode):
            raise Exception("bad argument. baseURL must be string")
        if not validateURL(baseURL):
            raise Exception("bad argument: badly formed baseURL")
        self.baseURL = baseURL
        if type(machines) not in (tuple, list):
            raise Exception("bad argument: machines must be list or tuple")
        self.machines = {}
        for (longName, machineName) in machines:
            self.machines[longName] = machineName

    def _handleSubmission(self, url, data, machine, memory, files=None):
        #
        # call this with a url, some data to be added to the form
        # as a post, and a couple optional argumetns.
        #
        #
        if not validateURL(url):
            raise Exception("bad argument: request must be valid URL")
        if type(data) is not dict:
            raise Exception("bad argument: data to be posted must be dict")
        if type(machine) not in (str, unicode):
            raise Exception("bad argument: machine must be a string")
        if type(memory)is not bool:
            raise Exception("bad argument: memory must be boolean")
        # all kinds of problems arise if you specify a machine for
        # cuckoo. intentionally breaking this for the moment.
        # if machine:
        #    data["machine"] = self.machines[machine]
        session = requests.Session()
        if memory:
            data['memory'] = memory
        if files:
            response = session.post(url, data=data, files=files)
        else:
            response = session.post(url, data=data)
        if response.status_code == 500:
            raise Exception("Internal error from Cuckoo submitting file")
        try:
            parsedResponse = response.json()
        except:
            raise Exception("error submitting to Cuckoo")
        finally:
            session.close()
        if "task_id" in parsedResponse:
            task_id = int(parsedResponse['task_id'])
        else:
            raise Exception("error submitting to Cuckoo")
        return task_id

    def submitFile(self,
                   fileHandle,
                   fileName,
                   machine="all",
                   memory=False):
        #
        # call with fileHandle that can be read, a fileName, a single machine
        # to run against, and a boolean whether it should also take a memory
        # image
        #
        if type(fileHandle) is not file:
            raise Exception("bad argument: fileHandle must be an open file")
        if type(fileName) not in (str, unicode):
            raise Exception("bad argument: fileName must be a string")
        if type(machine) not in (str, unicode):
            raise Exception("bad argument: machine must be string")
        if type(memory) is not bool:
            raise Exception("bad argument: memory must be boolean")
        if machine != "all":
            if machine not in self.machines:
                raise Exception("bad argument: unknown machine name")
        # note: cuckoo doesn't handle full set of UTF-8 well. It seems to 
        # want latin-1. In the meantime, requests seems to be forcing
        # all filenames to ascii. (ick.)
        fileName = fileName.encode("ascii", "replace")
        fileHandle.seek(0)
        submissionURL = self.baseURL + "tasks/create/file"
        data = {}
        files = {"file": (fileName, fileHandle)}
        taskID = self._handleSubmission(submissionURL,
                                        data,
                                        machine,
                                        memory,
                                        files)
        if taskID == -1:
            raise Exception("error submitting to Cuckoo")
        return taskID

    def submitURL(self, URL, machine="", memory=False):
        submissionURL = self.baseURL + "tasks/create/url"
        data = {"url": URL}
        return self._handleSubmission(submissionURL, data, machine, memory)

    def getTaskList(self):
        """
        gets the list of all tasks in Cuckoo.
        """
        taskURL = self.baseURL + "tasks/list"
        response = requests.get(taskURL)
        data = response.json()
        return data['tasks']

    def getReport(self, reportID):
        """
        gets the body html of a cuckoo report, allows you to embed it in
        another web page.
        """
        try:
            reportID = str(int(reportID))
        except:
            raise Exception("bad ID. Must be integer")
        requestURL = self.baseURL + "tasks/report/" + reportID + "/html"
        session = requests.Session()
        try:
            response = session.get(requestURL)
            text = copy.copy(response.text)
            bodyRE = re.search("<body>(.*)</body>", text, re.DOTALL)
            try:
                body = bodyRE.group(1)
            except IndexError:
                body = None
        except:
            body = "exception connecting to Cuckoo server"
        finally:
            session.close()
        return body

    def getJson(self, reportID):
        """
        Gets the json data of a report, for indexing in something like
        ElasticSearch

        """
        try:
            reportID = str(int(reportID))
        except:
            raise Exception("bad ID, must be an integer")
        requestURL = self.baseURL + "tasks/report/" + reportID + "/json"
        # have to make explicit sessions, and explicitly close the session
        #  in order to cause requests objects to be Garbage-Collected as
        # soon as possible. Also need to read response in chunks, 'cause
        # requests doesn't always free RAM if I read the json directly
        session = requests.Session()
        try:
            data = ""
            response = session.get(requestURL, stream=True)
            for chunk in response.iter_content(1024):
                if not chunk:
                    break
                data += chunk
            data = json.loads(data)
        except:
            data = {"error": "error connection to Cuckoo Server"}
        finally:
            session.close()
            response = None
            session = None
        return data
