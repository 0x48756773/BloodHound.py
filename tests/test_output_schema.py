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
Tests for the shape of the fields BloodHound reads as typed principals.

BloodHound decodes these into a struct with an ObjectIdentifier and an
ObjectType. A bare string in one of them fails the whole file with

    json: cannot unmarshal string into Go struct field
    User.AllowedToDelegate of type ein.TypedPrincipal

which is why the shape is worth pinning down in a test rather than trusting it
to stay right.
"""
import logging
import types
import unittest

from bloodhound.ad.computer import ADComputer
from bloodhound.ad.utils import ADUtils, SidCache

logging.disable(logging.CRITICAL)


def assert_typed_principals(testcase, value, field):
    testcase.assertIsInstance(value, list, '%s must be a list' % field)
    for item in value:
        testcase.assertIsInstance(
            item, dict,
            '%s entries must be objects, not bare strings - BloodHound rejects '
            'the whole file otherwise' % field)
        testcase.assertIn('ObjectIdentifier', item)
        testcase.assertIn('ObjectType', item)
        testcase.assertIsInstance(item['ObjectIdentifier'], str)
        testcase.assertIsInstance(item['ObjectType'], str)


class TestResolveDelegationTargets(unittest.TestCase):
    def setUp(self):
        self.cache = SidCache()
        self.cache.put('server1.corp.local', 'S-1-5-21-1-2-3-1105')

    def test_known_host_resolves_to_its_sid(self):
        targets = ADUtils.resolve_delegation_targets(['HOST/server1.corp.local'], self.cache)
        assert_typed_principals(self, targets, 'AllowedToDelegate')
        self.assertEqual(targets, [{'ObjectIdentifier': 'S-1-5-21-1-2-3-1105',
                                    'ObjectType': 'Computer'}])

    def test_unknown_host_falls_back_to_the_fqdn(self):
        targets = ADUtils.resolve_delegation_targets(['CIFS/other.corp.local'], self.cache)
        assert_typed_principals(self, targets, 'AllowedToDelegate')
        self.assertEqual(targets, [{'ObjectIdentifier': 'OTHER.CORP.LOCAL',
                                    'ObjectType': 'Computer'}])

    def test_netbios_only_target_is_dropped(self):
        # Nothing identifies this host, and claiming delegation to an
        # unidentifiable principal is worse than omitting it
        self.assertEqual(ADUtils.resolve_delegation_targets(['HOST/SERVER1'], self.cache), [])

    def test_malformed_spn_is_skipped(self):
        self.assertEqual(ADUtils.resolve_delegation_targets(['no-slash-here'], self.cache), [])

    def test_empty_and_missing_input(self):
        self.assertEqual(ADUtils.resolve_delegation_targets([], self.cache), [])
        self.assertEqual(ADUtils.resolve_delegation_targets(None, self.cache), [])

    def test_mixed_input_keeps_the_resolvable_ones(self):
        targets = ADUtils.resolve_delegation_targets(
            ['HOST/server1.corp.local', 'bad', 'HOST/SHORTNAME', 'LDAP/other.corp.local'],
            self.cache)
        assert_typed_principals(self, targets, 'AllowedToDelegate')
        self.assertEqual([t['ObjectIdentifier'] for t in targets],
                         ['S-1-5-21-1-2-3-1105', 'OTHER.CORP.LOCAL'])


class TestComputerDelegationOutput(unittest.TestCase):
    """
    The computer path builds AllowedToDelegate itself, so check the object it
    actually emits rather than only the helper.
    """
    def build(self, delegate_to):
        cache = SidCache()
        cache.put('server1.corp.local', 'S-1-5-21-1-2-3-1105')
        domain = types.SimpleNamespace(
            domain='corp.local',
            domain_object=types.SimpleNamespace(sid='S-1-5-21-1-2-3'),
            computersidcache=cache,
            objectresolver=None,
            auth=types.SimpleNamespace(auth_method='auto'),
            gpo_local_groups={})
        # objectprops parses the resource-based delegation descriptor, which
        # needs the schema GUID map; an empty one is enough since the entry
        # below carries no descriptor
        addc = types.SimpleNamespace(objecttype_guid_map={})
        computer = ADComputer(hostname='ws01.corp.local', samname='WS01$',
                              ad=domain, addc=addc, objectsid='S-1-5-21-1-2-3-1001')
        entry = {
            'attributes': {
                'objectSid': 'S-1-5-21-1-2-3-1001',
                'distinguishedName': 'CN=WS01,DC=CORP,DC=LOCAL',
                'sAMAccountName': 'WS01$',
                'userAccountControl': 4096,
                'msDS-AllowedToDelegateTo': delegate_to,
                'sIDHistory': [],
                'servicePrincipalName': [],
                'whencreated': 0,
                'lastlogon': 0,
                'lastlogontimestamp': 0,
                'pwdLastSet': 0,
            },
            'raw_attributes': {'sIDHistory': []},
        }
        # objectprops is what populates the delegation fields
        return computer.get_bloodhound_data(entry, {'objectprops'})

    def test_allowed_to_delegate_entries_are_typed_principals(self):
        data = self.build(['HOST/server1.corp.local', 'CIFS/other.corp.local'])
        assert_typed_principals(self, data['AllowedToDelegate'], 'Computer.AllowedToDelegate')
        self.assertEqual(len(data['AllowedToDelegate']), 2)

    def test_allowed_to_delegate_is_empty_without_delegation(self):
        data = self.build([])
        self.assertEqual(data['AllowedToDelegate'], [])

    def test_properties_keep_the_raw_spns(self):
        # The Properties copy is a plain list of strings and must stay that way
        data = self.build(['HOST/server1.corp.local'])
        self.assertEqual(data['Properties']['allowedtodelegate'], ['HOST/server1.corp.local'])

    def test_other_typed_principal_fields_keep_their_shape(self):
        data = self.build(['HOST/server1.corp.local'])
        for field in ('AllowedToAct', 'HasSIDHistory'):
            assert_typed_principals(self, data[field], 'Computer.%s' % field)
        for field in ('LocalAdmins', 'RemoteDesktopUsers', 'DcomUsers', 'PSRemoteUsers'):
            assert_typed_principals(self, data[field]['Results'], 'Computer.%s.Results' % field)


if __name__ == '__main__':
    unittest.main()


def cert_template_entry(guid, name, displayname, name_flag=0, enrollment_flag=0,
                        schemaversion=2, ekus=None):
    return {
        'attributes': {
            'objectGUID': '{%s}' % guid,
            'name': name,
            'displayName': displayname,
            'distinguishedName': 'CN=%s,CN=Certificate Templates,CN=Public Key Services,'
                                 'CN=Services,CN=Configuration,DC=CORP,DC=LOCAL' % name,
            'msPKI-Certificate-Name-Flag': name_flag,
            'msPKI-Enrollment-Flag': enrollment_flag,
            'msPKI-Template-Schema-Version': schemaversion,
            'msPKI-Cert-Template-OID': '1.3.6.1.4.1.311.21.8.1.2.3',
            'msPKI-RA-Signature': 0,
            'pKIExtendedKeyUsage': ekus if ekus is not None else [],
            'msPKI-Certificate-Application-Policy': [],
            'msPKI-RA-Application-Policies': [],
        },
        'raw_attributes': {},
    }


class CapturingCertEnumerator(object):
    """
    Runs the certificate enumerator against synthetic LDAP entries and keeps
    the objects it would have written, so the emitted properties can be checked
    without a directory or an output file.
    """
    def __init__(self, entries, published=(), ca_entries=()):
        import queue as queue_module
        from bloodhound.enumeration.certificates import CertificateServicesEnumerator

        self.captured = []
        enumerator = CertificateServicesEnumerator.__new__(CertificateServicesEnumerator)
        enumerator.collect = set()
        enumerator.disable_pooling = True
        enumerator.aclenumerator = types.SimpleNamespace(pool=None)
        enumerator.aceresolver = None
        enumerator.result_q = None
        enumerator.output_finalized = True
        enumerator.template_guids = {}
        enumerator.published_templates = set(name.lower() for name in published)
        enumerator.hostname_sids = {}
        enumerator.addomain = types.SimpleNamespace(
            domain='corp.local',
            domain_object=types.SimpleNamespace(sid='S-1-5-21-1-2-3'),
            dncache={},
            ca_registry_data={},
            computersidcache=SidCache())
        enumerator.addc = types.SimpleNamespace(
            objecttype_guid_map={},
            get_cert_templates=lambda include_properties=False, acl=False: entries,
            get_enterprise_cas=lambda include_properties=False, acl=False: ca_entries,
            get_ntauth_stores=lambda include_properties=False, acl=False: entries,
            search=lambda *a, **kw: [])

        captured = self.captured

        def start_writer(enumtype, filename):
            enumerator.result_q = queue_module.Queue()
            enumerator.output_finalized = False
            return None

        def finish(acl):
            enumerator.output_finalized = True
            while not enumerator.result_q.empty():
                captured.append(enumerator.result_q.get())

        enumerator.start_writer = start_writer
        enumerator.finish = finish
        self.enumerator = enumerator


class TestCertTemplateProperties(unittest.TestCase):
    """
    BloodHound gates the certificate escalation paths on these properties by
    name. A missing one is not a visible error - the templates import fine and
    simply never produce an edge - so the names and the enabled flag are worth
    asserting.
    """
    # Names BloodHound reads off a CertTemplate node
    REQUIRED = (
        'enabled', 'requiresmanagerapproval', 'authenticationenabled',
        'enrolleesuppliessubject', 'schemaversion', 'authorizedsignatures',
        'nosecurityextension', 'subjectaltrequireupn', 'subjectaltrequiredns',
        'subjectaltrequiredomaindns', 'subjectaltrequireemail', 'subjectaltrequirespn',
        'subjectrequireemail', 'ekus', 'effectiveekus', 'certificatenameflag',
        'enrollmentflag', 'certificateapplicationpolicy', 'applicationpolicies',
        'oid', 'validityperiod', 'renewalperiod', 'schannelauthenticationenabled',
    )

    def run_templates(self, entries, published=()):
        harness = CapturingCertEnumerator(entries, published=published)
        harness.enumerator.enumerate_cert_templates()
        return harness.captured

    def test_every_property_bloodhound_reads_is_present(self):
        templates = self.run_templates(
            [cert_template_entry('AAAAAAAA-0000-0000-0000-000000000001', 'WebServer', 'Web Server')])
        self.assertEqual(len(templates), 1)
        for name in self.REQUIRED:
            self.assertIn(name, templates[0]['Properties'],
                          '%s is read by BloodHound and must be emitted' % name)

    def test_enabled_is_true_when_a_ca_publishes_the_template(self):
        templates = self.run_templates(
            [cert_template_entry('AAAAAAAA-0000-0000-0000-000000000001', 'WebServer', 'Web Server')],
            published=['WebServer'])
        self.assertTrue(templates[0]['Properties']['enabled'])

    def test_enabled_matches_on_the_display_name_too(self):
        # Which of the two a CA lists depends on the template's schema version
        templates = self.run_templates(
            [cert_template_entry('AAAAAAAA-0000-0000-0000-000000000001', 'WebServer', 'Web Server')],
            published=['Web Server'])
        self.assertTrue(templates[0]['Properties']['enabled'])

    def test_enabled_is_false_when_no_ca_publishes_it(self):
        templates = self.run_templates(
            [cert_template_entry('AAAAAAAA-0000-0000-0000-000000000001', 'WebServer', 'Web Server')],
            published=['SomethingElse'])
        self.assertFalse(templates[0]['Properties']['enabled'])

    def test_esc1_relevant_flags_decode_from_the_name_flag(self):
        # 0x1 is CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, which ESC1 requires
        templates = self.run_templates(
            [cert_template_entry('AAAAAAAA-0000-0000-0000-000000000001', 'Offline', 'Offline',
                                 name_flag=0x00000001,
                                 ekus=['1.3.6.1.5.5.7.3.2'])],
            published=['Offline'])
        props = templates[0]['Properties']
        self.assertTrue(props['enrolleesuppliessubject'])
        self.assertTrue(props['authenticationenabled'])
        self.assertFalse(props['requiresmanagerapproval'])
        self.assertEqual(props['authorizedsignatures'], 0)

    def test_name_flag_with_the_high_bit_set_still_decodes(self):
        # AD stores this as a signed 32-bit integer, so a template requiring a
        # subject from AD arrives as a negative number
        templates = self.run_templates(
            [cert_template_entry('AAAAAAAA-0000-0000-0000-000000000001', 'User', 'User',
                                 name_flag=-1375731712)])
        props = templates[0]['Properties']
        self.assertTrue(props['subjectaltrequireupn'])
        self.assertFalse(props['enrolleesuppliessubject'])

    def test_manager_approval_decodes_from_the_enrollment_flag(self):
        templates = self.run_templates(
            [cert_template_entry('AAAAAAAA-0000-0000-0000-000000000001', 'T', 'T',
                                 enrollment_flag=0x00000002)])
        self.assertTrue(templates[0]['Properties']['requiresmanagerapproval'])


class TestNTAuthStoreProperties(unittest.TestCase):
    def test_thumbprints_are_emitted_as_a_node_property(self):
        """
        BloodHound matches an enterprise CA's certthumbprint against this list
        to build the NT auth trust that every certificate path runs through,
        and it reads it as a node property.
        """
        harness = CapturingCertEnumerator(
            [cert_template_entry('BBBBBBBB-0000-0000-0000-000000000001',
                                 'NTAuthCertificates', 'NTAuthCertificates')])
        harness.enumerator.enumerate_ca_store(
            harness.enumerator.addc.get_ntauth_stores,
            'ntauthstores', 'ntauthstore', 'ntauthstores.json')

        self.assertEqual(len(harness.captured), 1)
        store = harness.captured[0]
        self.assertIn('certthumbprints', store['Properties'])
        self.assertIsInstance(store['Properties']['certthumbprints'], list)
        # Kept at the top level as well, which is where SharpHound puts it
        self.assertIn('CertThumbprints', store)
        self.assertEqual(store['Properties']['certthumbprints'], store['CertThumbprints'])
        self.assertEqual(store['DomainSID'], 'S-1-5-21-1-2-3')


def enterprise_ca_entry(guid, name, dnshostname, templates=()):
    return {
        'attributes': {
            'objectGUID': '{%s}' % guid,
            'name': name,
            'dNSHostName': dnshostname,
            'distinguishedName': 'CN=%s,CN=Enrollment Services,CN=Public Key Services,'
                                 'CN=Services,CN=Configuration,DC=CORP,DC=LOCAL' % name,
            'certificateTemplates': list(templates),
            'flags': 0,
            'cACertificate': [],
        },
        'raw_attributes': {'cACertificate': []},
    }


class TestEnterpriseCAProperties(unittest.TestCase):
    def run_cas(self, entries, template_guids=None):
        harness = CapturingCertEnumerator([], ca_entries=entries)
        if template_guids:
            harness.enumerator.template_guids = template_guids
        harness.enumerator.enumerate_enterprise_cas()
        return harness.captured

    def test_domain_sid_is_emitted(self):
        """
        Without this the CA is not tied to the domain it issues for, which is
        what the root CA and NTAuth store objects use their DomainSID for too.
        """
        cas = self.run_cas([enterprise_ca_entry(
            'CCCCCCCC-0000-0000-0000-000000000001', 'Issuing-CA', 'ca01.corp.local')])
        self.assertEqual(len(cas), 1)
        self.assertEqual(cas[0]['DomainSID'], 'S-1-5-21-1-2-3')

    def test_published_templates_become_enabled_cert_templates(self):
        # This is what BloodHound turns into the PublishedTo edge
        cas = self.run_cas(
            [enterprise_ca_entry('CCCCCCCC-0000-0000-0000-000000000001', 'Issuing-CA',
                                 'ca01.corp.local', templates=['WebServer', 'Gone'])],
            template_guids={'webserver': 'AAAAAAAA-0000-0000-0000-000000000001'})
        ca = cas[0]
        self.assertEqual(ca['EnabledCertTemplates'],
                         [{'ObjectIdentifier': 'AAAAAAAA-0000-0000-0000-000000000001',
                           'ObjectType': 'CertTemplate'}])
        # A template a CA publishes but that we could not read is reported
        self.assertEqual(ca['Properties']['unresolvedpublishedtemplates'], ['Gone'])

    def test_ca_properties_bloodhound_reads_are_present(self):
        cas = self.run_cas([enterprise_ca_entry(
            'CCCCCCCC-0000-0000-0000-000000000001', 'Issuing-CA', 'ca01.corp.local')])
        for name in ('caname', 'dnshostname', 'certthumbprint', 'certname', 'certchain',
                     'hasbasicconstraints', 'basicconstraintpathlength',
                     'unresolvedpublishedtemplates'):
            self.assertIn(name, cas[0]['Properties'],
                          '%s is read by BloodHound and must be emitted' % name)
