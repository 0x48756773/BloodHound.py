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
