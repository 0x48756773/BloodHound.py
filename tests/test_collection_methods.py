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
Offline tests for the collection methods added on top of the original
BloodHound.py feature set: CertServices, CARegistry, DCRegistry, NTLMRegistry,
SMBInfo, WebClientService, LdapServices and GPOLocalGroup.

These cover the parts that can be exercised without a domain: flag decoding,
policy file parsing, security descriptor parsing and the collection method
resolution. The parts that talk to LDAP, SMB or the remote registry are not
covered here.
"""
import hashlib
import logging
import struct
import unittest

from bloodhound import resolve_collection_methods
from bloodhound.ad import adcs
from bloodhound.enumeration import acls
from bloodhound.enumeration import gpolocalgroup as gpo

# The tests deliberately feed malformed input to some parsers, which log at
# debug/warning level. Keep the test output readable.
logging.disable(logging.CRITICAL)


def encode_sid(sidstring):
    """
    Encode a SID string into its binary form, so tests can build security
    descriptors without depending on a live directory.
    """
    parts = sidstring.split('-')
    revision = int(parts[1])
    authority = int(parts[2])
    subauthorities = [int(part) for part in parts[3:]]
    data = struct.pack('B', revision)
    data += struct.pack('B', len(subauthorities))
    data += authority.to_bytes(6, 'big')
    for subauthority in subauthorities:
        data += struct.pack('<I', subauthority)
    return data


def build_ace(mask, sidstring, acetype=0x00, aceflags=0x00):
    body = struct.pack('<I', mask) + encode_sid(sidstring)
    return struct.pack('<BBH', acetype, aceflags, 4 + len(body)) + body


def build_security_descriptor(owner, aces):
    """
    Build a self-relative security descriptor with an owner and a DACL.
    """
    acl_body = b''.join(aces)
    acl_size = 8 + len(acl_body)
    acl = struct.pack('<BBHHH', 2, 0, acl_size, len(aces), 0) + acl_body

    header_size = 20
    owner_sid = encode_sid(owner)
    offset_owner = header_size
    offset_dacl = header_size + len(owner_sid)
    # SE_SELF_RELATIVE | SE_DACL_PRESENT
    control = 0x8004
    header = struct.pack('<BBHIIII', 1, 0, control, offset_owner, 0, 0, offset_dacl)
    return header + owner_sid + acl


class TestAdcsHelpers(unittest.TestCase):
    def filetime(self, seconds):
        # Validity and renewal periods are stored as a negative offset
        return struct.pack('<q', -(seconds * 10 ** 7))

    def test_filetime_to_span_uses_largest_exact_unit(self):
        self.assertEqual(adcs.filetime_to_span(self.filetime(365 * 86400)), '1 year')
        self.assertEqual(adcs.filetime_to_span(self.filetime(2 * 365 * 86400)), '2 years')
        self.assertEqual(adcs.filetime_to_span(self.filetime(6 * 7 * 86400)), '6 weeks')
        self.assertEqual(adcs.filetime_to_span(self.filetime(86400)), '1 day')
        self.assertEqual(adcs.filetime_to_span(self.filetime(8 * 3600)), '8 hours')

    def test_filetime_to_span_handles_missing_and_broken_values(self):
        self.assertIsNone(adcs.filetime_to_span(None))
        self.assertIsNone(adcs.filetime_to_span(b''))
        self.assertIsNone(adcs.filetime_to_span(b'\x01\x02'))
        # A zero period is not a span
        self.assertIsNone(adcs.filetime_to_span(struct.pack('<q', 0)))

    def test_has_flag(self):
        self.assertTrue(adcs.has_flag(0x00040002, adcs.CT_FLAG_PEND_ALL_REQUESTS))
        self.assertFalse(adcs.has_flag(0x00040000, adcs.CT_FLAG_PEND_ALL_REQUESTS))
        # Absent attributes arrive as None
        self.assertFalse(adcs.has_flag(None, adcs.CT_FLAG_PEND_ALL_REQUESTS))
        self.assertFalse(adcs.has_flag(0, adcs.CT_FLAG_PEND_ALL_REQUESTS))

    def test_effective_ekus_prefers_application_policies(self):
        self.assertEqual(adcs.effective_ekus(['1.2.3'], ['4.5.6']), ['4.5.6'])
        self.assertEqual(adcs.effective_ekus(['1.2.3'], []), ['1.2.3'])
        self.assertEqual(adcs.effective_ekus([], []), [])

    def test_authentication_detection(self):
        # No EKU at all means valid for any purpose, authentication included
        self.assertTrue(adcs.is_authentication_template([]))
        self.assertTrue(adcs.is_authentication_template([adcs.EKU_CLIENT_AUTHENTICATION]))
        self.assertTrue(adcs.is_authentication_template([adcs.EKU_SMART_CARD_LOGON]))
        self.assertTrue(adcs.is_authentication_template([adcs.EKU_ANY_PURPOSE]))
        self.assertFalse(adcs.is_authentication_template(['1.3.6.1.5.5.7.3.1']))

    def test_schannel_authentication_excludes_pkinit_only_ekus(self):
        # Smart card logon and PKINIT are Kerberos only, they do not enable
        # Schannel authentication
        self.assertFalse(adcs.is_authentication_template(
            [adcs.EKU_SMART_CARD_LOGON], schannel=True))
        self.assertFalse(adcs.is_authentication_template(
            [adcs.EKU_PKINIT_CLIENT_AUTHENTICATION], schannel=True))
        self.assertTrue(adcs.is_authentication_template(
            [adcs.EKU_CLIENT_AUTHENTICATION], schannel=True))

    def test_certificate_thumbprint(self):
        data = b'not a real certificate'
        self.assertEqual(adcs.certificate_thumbprint(data),
                         hashlib.sha1(data).hexdigest().upper())
        self.assertIsNone(adcs.certificate_thumbprint(None))

    def test_parse_certificate_survives_garbage(self):
        # An unparseable certificate must still yield its thumbprint rather
        # than failing the whole collection
        parsed = adcs.parse_certificate(b'garbage')
        self.assertEqual(parsed['thumbprint'], hashlib.sha1(b'garbage').hexdigest().upper())
        self.assertIsNone(parsed['name'])
        self.assertFalse(parsed['hasbasicconstraints'])


class TestCaSecurityParsing(unittest.TestCase):
    def test_parse_ca_security_maps_ca_specific_rights(self):
        sd = build_security_descriptor('S-1-5-21-1-2-3-512', [
            build_ace(acls.CA_ACCESS_MANAGE_CA, 'S-1-5-21-1-2-3-1105'),
            build_ace(acls.CA_ACCESS_MANAGE_CERTIFICATES, 'S-1-5-21-1-2-3-1106'),
            build_ace(acls.CA_ACCESS_ENROLL, 'S-1-5-21-1-2-3-513'),
        ])
        relations = acls.parse_ca_security(sd)
        found = set((relation['sid'], relation['rightname']) for relation in relations)
        self.assertIn(('S-1-5-21-1-2-3-1105', 'ManageCA'), found)
        self.assertIn(('S-1-5-21-1-2-3-1106', 'ManageCertificates'), found)
        self.assertIn(('S-1-5-21-1-2-3-513', 'Enroll'), found)

    def test_parse_ca_security_reports_combined_rights(self):
        mask = acls.CA_ACCESS_MANAGE_CA | acls.CA_ACCESS_ENROLL
        sd = build_security_descriptor('S-1-5-21-1-2-3-512',
                                       [build_ace(mask, 'S-1-5-21-1-2-3-1105')])
        rights = set(relation['rightname'] for relation in acls.parse_ca_security(sd)
                     if relation['sid'] == 'S-1-5-21-1-2-3-1105')
        self.assertEqual(rights, {'ManageCA', 'Enroll'})

    def test_parse_ca_security_skips_local_system(self):
        sd = build_security_descriptor('S-1-5-21-1-2-3-512', [
            build_ace(acls.CA_ACCESS_MANAGE_CA, 'S-1-5-18'),
        ])
        sids = set(relation['sid'] for relation in acls.parse_ca_security(sd))
        self.assertNotIn('S-1-5-18', sids)

    def test_parse_ca_security_handles_missing_and_broken_input(self):
        self.assertEqual(acls.parse_ca_security(None), [])
        self.assertEqual(acls.parse_ca_security(b''), [])
        self.assertEqual(acls.parse_ca_security(b'\x01\x02\x03'), [])

    def test_enrollment_agent_restrictions_lists_agents(self):
        sd = build_security_descriptor('S-1-5-21-1-2-3-512', [
            build_ace(0x00000001, 'S-1-5-21-1-2-3-1105'),
        ])
        restrictions = acls.parse_enrollment_agent_restrictions(sd)
        self.assertEqual(len(restrictions), 1)
        self.assertEqual(restrictions[0]['Agent'], 'S-1-5-21-1-2-3-1105')
        self.assertEqual(restrictions[0]['Targets'], [])

    def test_enrollment_agent_restrictions_handles_empty(self):
        self.assertEqual(acls.parse_enrollment_agent_restrictions(b''), [])
        self.assertEqual(acls.parse_enrollment_agent_restrictions(None), [])


class TestGpoLocalGroupParsing(unittest.TestCase):
    def test_local_group_key_by_sid_and_name(self):
        self.assertEqual(gpo.local_group_key('S-1-5-32-544'), 'admins')
        self.assertEqual(gpo.local_group_key('*S-1-5-32-555'), 'rdp')
        self.assertEqual(gpo.local_group_key('S-1-5-32-562'), 'dcom')
        self.assertEqual(gpo.local_group_key('S-1-5-32-580'), 'psremote')
        self.assertEqual(gpo.local_group_key('Administrators (built-in)'), 'admins')
        self.assertEqual(gpo.local_group_key('BUILTIN\\Administrators'), 'admins')
        self.assertIsNone(gpo.local_group_key('Power Users'))
        self.assertIsNone(gpo.local_group_key(''))
        self.assertIsNone(gpo.local_group_key(None))

    def test_parse_restricted_groups_members_and_memberof(self):
        inf = '\n'.join([
            '[Unicode]',
            'Unicode=yes',
            '[Group Membership]',
            '*S-1-5-32-544__Memberof =',
            '*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1105,CORP\\Helpdesk',
            '*S-1-5-32-555__Members = *S-1-5-21-1-2-3-1106',
            'Power Users__Memberof = *S-1-5-32-544',
            '[Version]',
            'signature="$CHICAGO$"',
        ])
        result = gpo.parse_restricted_groups(inf)
        self.assertIn(('admins', '*S-1-5-21-1-2-3-1105'), result)
        self.assertIn(('admins', 'CORP\\Helpdesk'), result)
        self.assertIn(('rdp', '*S-1-5-21-1-2-3-1106'), result)
        # Memberof means the named group is placed into the local group
        self.assertIn(('admins', 'Power Users'), result)

    def test_parse_restricted_groups_ignores_other_sections_and_groups(self):
        inf = '\n'.join([
            '[Registry Values]',
            '*S-1-5-32-544__Members = *S-1-5-21-1-2-3-9999',
            '[Group Membership]',
            'Power Users__Members = *S-1-5-21-1-2-3-1105',
        ])
        self.assertEqual(gpo.parse_restricted_groups(inf), [])

    def test_parse_restricted_groups_handles_empty_input(self):
        self.assertEqual(gpo.parse_restricted_groups(''), [])

    def test_parse_gpp_groups(self):
        xml = '''<?xml version="1.0" encoding="utf-8"?>
        <Groups clsid="{3125E937}">
          <Group clsid="{6D4A79E4}" name="Administrators (built-in)">
            <Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
              <Members>
                <Member name="CORP\\Helpdesk" action="ADD" sid="S-1-5-21-1-2-3-1105"/>
                <Member name="CORP\\Former" action="REMOVE" sid="S-1-5-21-1-2-3-1199"/>
              </Members>
            </Properties>
          </Group>
          <Group clsid="{x}" name="Remote Desktop Users">
            <Properties action="D" groupName="Remote Desktop Users">
              <Members><Member name="CORP\\X" action="ADD" sid="S-1-5-21-1-2-3-1200"/></Members>
            </Properties>
          </Group>
        </Groups>'''
        result = gpo.parse_gpp_groups(xml)
        # Only the added member of the updated group counts
        self.assertEqual(result, [('admins', 'S-1-5-21-1-2-3-1105')])

    def test_parse_gpp_groups_handles_broken_xml(self):
        self.assertEqual(gpo.parse_gpp_groups('<Groups><not closed>'), [])
        self.assertEqual(gpo.parse_gpp_groups(''), [])

    def test_parse_gplink_skips_disabled_links(self):
        gplink = ('[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,'
                  'cn=system,DC=corp,DC=local;0]'
                  '[LDAP://cn={AAAAAAAA-0000-0000-0000-000000000000},cn=policies,'
                  'cn=system,DC=corp,DC=local;1]'
                  '[LDAP://cn={BBBBBBBB-0000-0000-0000-000000000000},cn=policies,'
                  'cn=system,DC=corp,DC=local;2]')
        linked = gpo.parse_gplink(gplink)
        self.assertEqual(len(linked), 2)
        self.assertTrue(linked[0].startswith('CN={31B2F340'))
        # The enforced link (option 2) is kept, the disabled one (option 1) is not
        self.assertTrue(linked[1].startswith('CN={BBBBBBBB'))

    def test_parse_gplink_handles_empty(self):
        self.assertEqual(gpo.parse_gplink(''), [])
        self.assertEqual(gpo.parse_gplink(None), [])

    def test_gpcfilesyspath_to_share(self):
        share, path = gpo.gpcfilesyspath_to_share(
            r'\\corp.local\SysVol\corp.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}')
        self.assertEqual(share, 'SysVol')
        self.assertEqual(path, r'corp.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}')

    def test_gpcfilesyspath_to_share_handles_bad_input(self):
        self.assertEqual(gpo.gpcfilesyspath_to_share(''), (None, None))
        self.assertEqual(gpo.gpcfilesyspath_to_share(None), (None, None))
        self.assertEqual(gpo.gpcfilesyspath_to_share(r'\\server'), (None, None))

    def test_decode_policy_file(self):
        # GptTmpl.inf is UTF-16 with a BOM in practice
        self.assertEqual(gpo.decode_policy_file('[Group Membership]'.encode('utf-16')),
                         '[Group Membership]')
        self.assertEqual(gpo.decode_policy_file(b'[Group Membership]'), '[Group Membership]')
        self.assertEqual(gpo.decode_policy_file(b''), '')


class FakeDomain(object):
    """
    The slice of the AD object that building a computer's output touches.
    """
    def __init__(self, gpo_local_groups=None):
        self.domain = 'corp.local'
        self.domain_object = type('ADDomain', (), {'sid': 'S-1-5-21-1-2-3'})()
        self.gpo_local_groups = gpo_local_groups or {}


def make_entry(sid, dn='CN=WS01,OU=WORKSTATIONS,DC=CORP,DC=LOCAL', uac=4096):
    return {
        'attributes': {
            'objectSid': sid,
            'distinguishedName': dn,
            'sAMAccountName': 'WS01$',
            'userAccountControl': uac,
        },
        'raw_attributes': {},
    }


class TestComputerLocalGroupOutput(unittest.TestCase):
    """
    GPO delivered membership has to reach the computer objects, including for
    hosts that were never contacted - that is the point of the method.
    """
    def setUp(self):
        from bloodhound.ad.computer import ADComputer
        self.ADComputer = ADComputer
        self.sid = 'S-1-5-21-1-2-3-1001'
        self.helpdesk = {'ObjectIdentifier': 'S-1-5-21-1-2-3-1105', 'ObjectType': 'Group'}

    def build(self, collect, gpo_local_groups=None, permanentfailure=False):
        domain = FakeDomain(gpo_local_groups)
        computer = self.ADComputer(hostname='ws01.corp.local', samname='WS01$',
                                   ad=domain, objectsid=self.sid)
        computer.permanentfailure = permanentfailure
        return computer.get_bloodhound_data(make_entry(self.sid), collect)

    def test_gpo_membership_is_merged_into_local_admins(self):
        data = self.build({'gpolocalgroup'},
                          {self.sid: {'admins': [self.helpdesk], 'rdp': [],
                                      'dcom': [], 'psremote': []}})
        self.assertTrue(data['LocalAdmins']['Collected'])
        self.assertEqual(data['LocalAdmins']['Results'], [self.helpdesk])
        self.assertEqual(data['RemoteDesktopUsers']['Results'], [])

    def test_gpo_membership_survives_an_unreachable_host(self):
        # The whole point of reading SYSVOL is that it works without the host
        data = self.build({'gpolocalgroup'},
                          {self.sid: {'admins': [self.helpdesk], 'rdp': [],
                                      'dcom': [], 'psremote': []}},
                          permanentfailure=True)
        self.assertTrue(data['LocalAdmins']['Collected'])
        self.assertEqual(data['LocalAdmins']['Results'], [self.helpdesk])

    def test_gpo_membership_is_not_duplicated_with_host_results(self):
        domain = FakeDomain({self.sid: {'admins': [self.helpdesk], 'rdp': [],
                                        'dcom': [], 'psremote': []}})
        computer = self.ADComputer(hostname='ws01.corp.local', samname='WS01$',
                                   ad=domain, objectsid=self.sid)
        # The same principal was also found on the host itself
        computer.admins = [dict(self.helpdesk)]
        data = computer.get_bloodhound_data(make_entry(self.sid), {'gpolocalgroup', 'localadmin'})
        self.assertEqual(data['LocalAdmins']['Results'], [self.helpdesk])

    def test_without_the_method_nothing_is_merged(self):
        data = self.build({'localadmin'},
                          {self.sid: {'admins': [self.helpdesk], 'rdp': [],
                                      'dcom': [], 'psremote': []}})
        self.assertEqual(data['LocalAdmins']['Results'], [])

    def test_isdc_property_is_reported(self):
        domain = FakeDomain()
        computer = self.ADComputer(hostname='dc01.corp.local', samname='DC01$',
                                   ad=domain, objectsid=self.sid)
        # 0x2000 is the server trust account bit that marks a DC
        data = computer.get_bloodhound_data(make_entry(self.sid, uac=0x2000), set())
        self.assertTrue(data['Properties']['isdc'])

    def test_host_properties_are_merged_into_properties(self):
        domain = FakeDomain()
        computer = self.ADComputer(hostname='ws01.corp.local', samname='WS01$',
                                   ad=domain, objectsid=self.sid)
        computer.host_properties = {'smbsigning': True, 'webclientrunning': False,
                                    'ldapavailable': False}
        data = computer.get_bloodhound_data(make_entry(self.sid), {'smbinfo'})
        self.assertTrue(data['Properties']['smbsigning'])
        self.assertFalse(data['Properties']['webclientrunning'])
        self.assertFalse(data['Properties']['ldapavailable'])


class TestCollectionMethodResolution(unittest.TestCase):
    def test_new_methods_are_accepted(self):
        for method in ('CertServices', 'CARegistry', 'DCRegistry', 'NTLMRegistry',
                       'SMBInfo', 'WebClientService', 'LdapServices', 'GPOLocalGroup'):
            self.assertIn(method.lower(), resolve_collection_methods(method),
                          '%s should be a valid collection method' % method)

    def test_caregistry_pulls_in_certservices(self):
        # The CA registry data is written out with the enterprise CA objects,
        # so collecting it alone would discard the results
        self.assertEqual(resolve_collection_methods('CARegistry'),
                         {'caregistry', 'certservices'})

    def test_dconly_includes_only_methods_that_need_no_member_hosts(self):
        dconly = resolve_collection_methods('DCOnly')
        self.assertIn('certservices', dconly)
        self.assertIn('gpolocalgroup', dconly)
        for method in ('caregistry', 'dcregistry', 'ntlmregistry', 'smbinfo',
                       'webclientservice', 'ldapservices', 'localadmin', 'session'):
            self.assertNotIn(method, dconly)

    def test_all_includes_the_new_methods_but_not_loggedon(self):
        every = resolve_collection_methods('All')
        for method in ('certservices', 'caregistry', 'dcregistry', 'ntlmregistry',
                       'smbinfo', 'webclientservice', 'ldapservices', 'gpolocalgroup'):
            self.assertIn(method, every)
        self.assertNotIn('loggedon', every)

    def test_default_is_unchanged(self):
        self.assertEqual(resolve_collection_methods('Default'),
                         {'group', 'localadmin', 'session', 'trusts'})

    def test_invalid_method_is_rejected(self):
        self.assertFalse(resolve_collection_methods('NotAMethod'))
        self.assertFalse(resolve_collection_methods('Group,NotAMethod'))


if __name__ == '__main__':
    unittest.main()
