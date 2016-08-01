# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import codecs
import calendar
from datetime import datetime

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError


def default(obj):
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)

class InvalidDnsRecord(Exception):
    pass

class DnsDump(Report):
    """Logs DNS data in a file."""

    def record_to_str(self, record):
        domain = record['request']
        rtype = record['type']
        rdata = ''
        answers = record['answers']
        for answer in answers:
            if answer['type'] == rtype:
                rdata = answer['data']

        # if query type record not found, get first dns answer
        if rdata == '':
            if len(answers) > 0:
                rtype = answers[0]['type']
                rdata = answers[0]['data']
            else:
                raise InvalidDnsRecord('rdata is empty')
        return "{}\t{}\t{}\t{}\n".format(datetime.now().isoformat(), domain, rtype, rdata)

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        try:
            path = os.path.join(self.options.get('output_path'), '{}.log'.format(self.task['id']))

            records = []

            if results.get('network'):
                if results['network'].get('dns'):
                    records = results['network']['dns']

            with codecs.open(path, "w", "utf-8") as report:
                for query in records:
                    try:
                        record = self.record_to_str(query)
                    except InvalidDnsRecord:
                        continue
                    report.write(record)

        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to log DNS data: %s" % e)
