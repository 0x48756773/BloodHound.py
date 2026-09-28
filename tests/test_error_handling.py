####################
#
# Copyright (c) 2018 Fox-IT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################
"""
Tests for recovering from a lost LDAP connection partway through a collection.

A collection against a large domain runs for a long time, and a domain
controller dropping one connection used to end it with a traceback and a
half-written output file. These cover both halves of that: retrying the query
on a reconnected socket, and closing the output file off so what was already
collected stays importable.
"""
import json
import logging
import os
import queue
import shutil
import tempfile
import threading
import types
import unittest

import dns.resolver
from ldap3.core.exceptions import (
    LDAPCommunicationError,
    LDAPSessionTerminatedByServerError,
    LDAPSocketReceiveError,
)

from bloodhound.ad.domain import ADDC
from bloodhound.enumeration.memberships import MembershipEnumerator
from bloodhound.enumeration.outputworker import OutputWorker

logging.disable(logging.CRITICAL)


class FakeSearcher(object):
    """
    Stands in for an ldap3 Connection. Raises on the first `failures` calls,
    which is what a reset socket looks like from paged_search.
    """
    def __init__(self, failures=0, error=LDAPSocketReceiveError):
        self.calls = 0
        self.failures = failures
        self.error = error
        # paged_search is reached through connection.extend.standard
        self.extend = self
        self.standard = self

    def paged_search(self, *args, **kwargs):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error('error receiving data: [Errno 104] Connection reset by peer')
        return [{'type': 'searchResEntry',
                 'attributes': {'distinguishedName': 'CN=Someone,DC=corp,DC=local'}}]


def make_addc(searcher=None, gcsearcher=None):
    """
    An ADDC with just the attributes the query paths touch, so the retry logic
    can be exercised without a directory.
    """
    addc = ADDC.__new__(ADDC)
    addc.hostname = 'dc01.corp.local'
    addc.ldap = searcher
    addc.gcldap = gcsearcher
    addc.resolverldap = searcher
    addc.objecttype_guid_map = {}
    addc.ad = types.SimpleNamespace(baseDN='DC=corp,DC=local')
    return addc


class TestLdapGetSingleRetry(unittest.TestCase):
    """
    ldap_get_single is called once per unresolved group member, so on a large
    domain it runs tens of thousands of times. It had no handling for a lost
    connection at all, which is what ended the reported collection.
    """
    def test_retries_once_and_succeeds(self):
        searcher = FakeSearcher(failures=1)
        addc = make_addc(searcher)
        reconnects = []
        addc.ldap_reconnect = lambda use_gc=False, use_resolver=False: (
            reconnects.append((use_gc, use_resolver)) or True)

        result = addc.ldap_get_single('CN=Someone,DC=corp,DC=local')

        self.assertIsNotNone(result)
        self.assertEqual(searcher.calls, 2, 'should have retried the query once')
        self.assertEqual(reconnects, [(False, False)])

    def test_gives_up_after_one_retry(self):
        # Two failures in a row means the reconnect did not help
        searcher = FakeSearcher(failures=2)
        addc = make_addc(searcher)
        addc.ldap_reconnect = lambda use_gc=False, use_resolver=False: True

        result = addc.ldap_get_single('CN=Someone,DC=corp,DC=local')

        self.assertIsNone(result, 'an unresolvable member is skipped, not fatal')
        self.assertEqual(searcher.calls, 2, 'should not retry forever')

    def test_does_not_retry_when_reconnect_fails(self):
        searcher = FakeSearcher(failures=1)
        addc = make_addc(searcher)
        addc.ldap_reconnect = lambda use_gc=False, use_resolver=False: False

        self.assertIsNone(addc.ldap_get_single('CN=Someone,DC=corp,DC=local'))
        self.assertEqual(searcher.calls, 1, 'no point querying a connection we could not restore')

    def test_reconnects_the_connection_the_query_used(self):
        # A Global Catalog query must reconnect the GC, not the main connection
        gcsearcher = FakeSearcher(failures=1)
        addc = make_addc(FakeSearcher(), gcsearcher)
        reconnects = []
        addc.ldap_reconnect = lambda use_gc=False, use_resolver=False: (
            reconnects.append((use_gc, use_resolver)) or True)

        addc.ldap_get_single('CN=Someone,DC=corp,DC=local', use_gc=True)

        self.assertEqual(reconnects, [(True, False)])

    def test_handles_a_session_torn_down_by_the_server(self):
        # Not just a reset socket: every ldap3 communication error is transient
        searcher = FakeSearcher(failures=1, error=LDAPSessionTerminatedByServerError)
        addc = make_addc(searcher)
        addc.ldap_reconnect = lambda use_gc=False, use_resolver=False: True

        self.assertIsNotNone(addc.ldap_get_single('CN=Someone,DC=corp,DC=local'))
        self.assertEqual(searcher.calls, 2)


class TestSearchRetry(unittest.TestCase):
    def test_search_reconnects_the_global_catalog(self):
        """
        search() already retried, but always reconnected the main connection.
        A GC query would then retry on the same dead GC socket.
        """
        gcsearcher = FakeSearcher(failures=1)
        addc = make_addc(FakeSearcher(), gcsearcher)
        reconnects = []
        addc.ldap_reconnect = lambda use_gc=False, use_resolver=False: (
            reconnects.append((use_gc, use_resolver)) or True)

        results = list(addc.search(search_filter='(objectClass=*)', use_gc=True))

        self.assertEqual(reconnects, [(True, False)], 'the GC is what needed reconnecting')
        self.assertEqual(len(results), 1, 'the retry should have produced the entry')

    def test_search_covers_non_generator_searches(self):
        """
        With generator=False, paged_search contacts the server when it is
        called rather than when the result is iterated. That call used to sit
        outside the try block, so those searches - get_memberships among them -
        were never covered by the retry at all.
        """
        searcher = FakeSearcher(failures=1)
        addc = make_addc(searcher)
        addc.ldap_reconnect = lambda use_gc=False, use_resolver=False: True

        results = list(addc.search(search_filter='(objectClass=*)', generator=False))

        self.assertEqual(searcher.calls, 2)
        self.assertEqual(len(results), 1)

    def test_search_gives_up_when_reconnect_fails(self):
        searcher = FakeSearcher(failures=1)
        addc = make_addc(searcher)
        addc.ldap_reconnect = lambda use_gc=False, use_resolver=False: False

        # Must not raise, and must not retry on a connection we never restored
        self.assertEqual(list(addc.search(search_filter='(objectClass=*)')), [])
        self.assertEqual(searcher.calls, 1)


class TestGcConnectResolutionFailure(unittest.TestCase):
    def test_returns_false_when_no_gc_resolves(self):
        """
        Every Global Catalog failing to resolve used to leave the IP variable
        unbound and raise UnboundLocalError. Reachable now that a reconnect
        calls this.
        """
        addc = ADDC.__new__(ADDC)
        addc.hostname = 'dc01.corp.local'
        addc.gcldap = None

        def always_nxdomain(*args, **kwargs):
            raise dns.resolver.NXDOMAIN()

        addc.ad = types.SimpleNamespace(
            gcs=lambda: ['gc01.corp.local', 'gc02.corp.local'],
            dnsresolver=types.SimpleNamespace(query=always_nxdomain),
            dns_tcp=False,
            baseDN='DC=corp,DC=local',
            auth=None)

        self.assertFalse(addc.gc_connect())


class TestOutputSurvivesFailure(unittest.TestCase):
    """
    The point of all of this: a step that dies partway must still leave a file
    BloodHound can import, holding everything collected up to that point.
    """
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tmpdir, 'groups.json')

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def make_enumerator(self):
        enumerator = MembershipEnumerator.__new__(MembershipEnumerator)
        enumerator.collect = set()
        enumerator.disable_pooling = True
        enumerator.aclenumerator = types.SimpleNamespace(pool=None)
        enumerator.result_q = None
        enumerator.output_finalized = True
        return enumerator

    def start_writer(self, enumerator):
        enumerator.result_q = queue.Queue()
        enumerator.output_finalized = False
        worker = threading.Thread(target=OutputWorker.membership_write_worker,
                                  args=(enumerator.result_q, 'groups', self.filename))
        worker.daemon = True
        worker.start()

    def test_file_is_valid_json_when_a_step_raises(self):
        enumerator = self.make_enumerator()

        def failing_step():
            self.start_writer(enumerator)
            enumerator.result_q.put({'ObjectIdentifier': 'S-1-5-21-1-2-3-1105'})
            enumerator.result_q.put({'ObjectIdentifier': 'S-1-5-21-1-2-3-1106'})
            raise LDAPCommunicationError('connection reset by peer')

        with self.assertRaises(LDAPCommunicationError):
            enumerator.run_step(failing_step)

        # The exception still reaches the caller, but the file is complete
        with open(self.filename) as handle:
            data = json.load(handle)
        self.assertEqual(len(data['data']), 2, 'objects collected before the failure are kept')
        self.assertEqual(data['meta']['type'], 'groups')
        self.assertEqual(data['meta']['count'], 2)

    def test_finalize_is_idempotent(self):
        """
        The normal path finalizes, then run_step's finally calls it again. A
        second None would never be consumed and the join would block forever.
        """
        enumerator = self.make_enumerator()

        def normal_step():
            self.start_writer(enumerator)
            enumerator.result_q.put({'ObjectIdentifier': 'S-1-5-21-1-2-3-1105'})
            enumerator.finalize_output(False)

        finished = threading.Event()

        def run():
            enumerator.run_step(normal_step)
            finished.set()

        thread = threading.Thread(target=run)
        thread.daemon = True
        thread.start()
        self.assertTrue(finished.wait(timeout=10), 'finalizing twice should not block')

        with open(self.filename) as handle:
            data = json.load(handle)
        self.assertEqual(data['meta']['count'], 1)

    def test_finalize_without_an_open_file_is_a_noop(self):
        enumerator = self.make_enumerator()
        # result_q is None here; this must not raise
        enumerator.finalize_output(True)


if __name__ == '__main__':
    unittest.main()
