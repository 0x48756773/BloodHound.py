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
GPOLocalGroup collection.

Group Policy can put principals into the local Administrators, Remote Desktop
Users, Distributed COM Users and Remote Management Users groups of every
computer a GPO applies to. Two mechanisms do this, and a domain can use both at
once:

  * Restricted Groups, in the MACHINE half of the GPO's GptTmpl.inf
  * Group Policy Preferences, in Preferences\\Groups\\Groups.xml

Both live in SYSVOL, so this reads them over SMB from a domain controller and
maps the result onto the computers in the organisational units the GPO is
linked to. Nothing is asked of the computers themselves, which is the point:
this finds local admins on hosts that are switched off or unreachable.
"""
from __future__ import unicode_literals

import logging
import re
import xml.etree.ElementTree as ET
from io import BytesIO

from impacket.smbconnection import SessionError

from bloodhound.ad.computer import ADComputer
from bloodhound.ad.utils import ADUtils, AceResolver

# The local groups BloodHound tracks, by the SID they always have.
LOCAL_GROUP_SIDS = {
    'S-1-5-32-544': 'admins',
    'S-1-5-32-555': 'rdp',
    'S-1-5-32-562': 'dcom',
    'S-1-5-32-580': 'psremote',
}

# Restricted Groups and GPP entries may name the group instead of using its
# SID. These are the default English names; a localised install writes the
# SID instead, which is why the SID table above is the primary one.
LOCAL_GROUP_NAMES = {
    'administrators': 'admins',
    'remote desktop users': 'rdp',
    'distributed com users': 'dcom',
    'remote management users': 'psremote',
}

# Where in a GPO the two mechanisms store their configuration
GPTTMPL_PATH = 'MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf'
GROUPS_XML_PATH = 'MACHINE\\Preferences\\Groups\\Groups.xml'

# gPLink option bits. Bit 0 disables the link entirely, which is worth
# honouring since a disabled link grants nothing.
GPLINK_OPTION_DISABLED = 1

GPLINK_RE = re.compile(r'\[LDAP://(?P<dn>[^;]+);(?P<options>\d+)\]', re.IGNORECASE)


def local_group_key(identifier):
    """
    Map a group SID or name from a policy file to one of the local groups we
    track, or None when it is some other group we do not care about.
    """
    if not identifier:
        return None
    value = identifier.strip().strip('*')
    if value.upper() in LOCAL_GROUP_SIDS:
        return LOCAL_GROUP_SIDS[value.upper()]
    # GPP writes names like "Administrators (built-in)"
    name = value.lower()
    if '(' in name:
        name = name.split('(')[0].strip()
    # Restricted Groups may use a qualified name
    if '\\' in name:
        name = name.split('\\')[-1].strip()
    return LOCAL_GROUP_NAMES.get(name)


def decode_policy_file(data):
    """
    Decode a policy file from SYSVOL. GptTmpl.inf is UTF-16 with a BOM in
    practice, but not always, so fall back rather than lose the file.
    """
    if not data:
        return ''
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        try:
            return data.decode('utf-16')
        except UnicodeDecodeError:
            pass
    for encoding in ('utf-8-sig', 'utf-16-le', 'latin-1'):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return ''


def parse_gplink(gplink):
    """
    Split a gPLink attribute into the GPO DNs it links, skipping disabled
    links. The attribute is a run of [LDAP://<dn>;<options>] entries.
    """
    if not gplink:
        return []
    linked = []
    for match in GPLINK_RE.finditer(gplink):
        try:
            options = int(match.group('options'))
        except ValueError:
            options = 0
        if options & GPLINK_OPTION_DISABLED:
            continue
        linked.append(match.group('dn').strip().upper())
    return linked


def parse_restricted_groups(content):
    """
    Extract local group membership from the [Group Membership] section of a
    GptTmpl.inf.

    The section holds two kinds of key: "<group>__Members", listing who belongs
    to that group, and "<group>__Memberof", listing which groups that group
    belongs to. Both can put a principal into a local group, so both are read.

    Returns a list of (local group key, member identifier) pairs.
    """
    results = []
    in_section = False
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        if line.startswith('['):
            in_section = line.lower().startswith('[group membership]')
            continue
        if not in_section or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        members = [member.strip() for member in value.split(',') if member.strip()]
        if not members:
            continue
        if key.lower().endswith('__members'):
            group = local_group_key(key[:-len('__Members')])
            if group:
                results.extend((group, member) for member in members)
        elif key.lower().endswith('__memberof'):
            # This group is a member of the listed groups
            member = key[:-len('__Memberof')].strip()
            for target in members:
                group = local_group_key(target)
                if group:
                    results.append((group, member))
    return results


def parse_gpp_groups(content):
    """
    Extract local group membership from a Group Policy Preferences Groups.xml.

    Returns a list of (local group key, member identifier) pairs. Entries that
    delete a group or remove a member are skipped: this collection describes who
    gains access, and modelling removals would need the pre-existing membership
    the file does not contain.
    """
    results = []
    if not content:
        return results
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        logging.debug('Could not parse Groups.xml: %s', exc)
        return results

    for group in root.iter('Group'):
        properties = group.find('Properties')
        if properties is None:
            continue
        # C = create, U = update, R = replace, D = delete
        if (properties.get('action') or 'U').upper() == 'D':
            continue
        identifier = (properties.get('groupSid')
                      or properties.get('groupName')
                      or group.get('name'))
        key = local_group_key(identifier)
        if not key:
            continue
        members = properties.find('Members')
        if members is None:
            continue
        for member in members.iter('Member'):
            if (member.get('action') or 'ADD').upper() != 'ADD':
                continue
            value = member.get('sid') or member.get('name')
            if value:
                results.append((key, value))
    return results


def gpcfilesyspath_to_share(path):
    """
    Split a gPCFileSysPath (\\\\domain\\SysVol\\domain\\Policies\\{GUID}) into
    the share name and the path within it, so it can be read from whichever DC
    we are connected to rather than the server named in the attribute.
    """
    if not path:
        return None, None
    parts = [part for part in path.replace('/', '\\').split('\\') if part]
    if len(parts) < 2:
        return None, None
    # parts[0] is the server, parts[1] the share
    return parts[1], '\\'.join(parts[2:])


class GPOLocalGroupEnumerator(object):
    """
    Resolves GPO-delivered local group membership and records it per computer
    on the AD object, where the computer enumerator picks it up.
    """

    def __init__(self, addomain, addc, collect):
        self.addomain = addomain
        self.addc = addc
        self.collect = collect
        self.aceresolver = AceResolver(addomain, addomain.objectresolver)
        self.smbconnection = None
        # Cache of resolved member identifiers, since one group tends to show
        # up in many GPOs
        self.member_cache = {}

    def connect_sysvol(self):
        """
        Open an SMB connection to a domain controller to read SYSVOL from.
        """
        dc = ADComputer(hostname=self.addc.hostname, samname=None,
                        ad=self.addomain, addc=self.addc)
        if not dc.try_connect():
            logging.warning('Could not connect to %s to read SYSVOL', self.addc.hostname)
            return None
        connection = dc.ensure_smb_connection()
        if connection is None:
            logging.warning('Could not establish an SMB session with %s to read SYSVOL',
                            self.addc.hostname)
        return connection

    def read_sysvol_file(self, share, path):
        """
        Read a file from SYSVOL. A missing file is normal - most GPOs configure
        neither mechanism - so that is logged at debug level only.
        """
        buf = BytesIO()
        try:
            self.smbconnection.getFile(share, path, buf.write)
        except SessionError as exc:
            message = str(exc)
            if 'STATUS_OBJECT_NAME_NOT_FOUND' in message or 'STATUS_OBJECT_PATH_NOT_FOUND' in message:
                logging.debug('No %s in this GPO', path)
            else:
                logging.debug('Could not read %s: %s', path, message)
            return None
        except Exception as exc:
            logging.debug('Could not read %s: %s', path, exc)
            return None
        return buf.getvalue()

    def resolve_member(self, identifier):
        """
        Turn a member reference from a policy file into a BloodHound principal.

        References are either a SID (optionally prefixed with * in
        GptTmpl.inf) or an account name, which may be qualified with a domain.
        """
        if identifier in self.member_cache:
            return self.member_cache[identifier]

        value = identifier.strip()
        resolved = None
        if value.startswith('*'):
            value = value[1:]
        if value.upper().startswith('S-1-'):
            resolved = self.aceresolver.resolve_sid(value.upper())
        else:
            samname = value.split('\\')[-1].strip()
            if samname:
                entries = self.addomain.objectresolver.resolve_samname(
                    samname, use_gc=self.addomain.num_domains > 1)
                if entries:
                    entry = ADUtils.resolve_ad_entry(entries[0])
                    resolved = {
                        'ObjectIdentifier': entry['objectid'],
                        'ObjectType': entry['type'].capitalize(),
                    }
                else:
                    logging.debug('Could not resolve GPO group member %s', identifier)

        if resolved is not None and not resolved.get('ObjectIdentifier'):
            resolved = None
        self.member_cache[identifier] = resolved
        return resolved

    def collect_gpo_memberships(self, gpcfilesyspath):
        """
        Read both policy files of a single GPO and return the local group
        membership they configure, as (local group key, member identifier).
        """
        share, base = gpcfilesyspath_to_share(gpcfilesyspath)
        if not share:
            logging.debug('Could not make sense of GPO path %s', gpcfilesyspath)
            return []

        memberships = []
        inf = self.read_sysvol_file(share, '%s\\%s' % (base, GPTTMPL_PATH))
        if inf:
            memberships.extend(parse_restricted_groups(decode_policy_file(inf)))
        xml = self.read_sysvol_file(share, '%s\\%s' % (base, GROUPS_XML_PATH))
        if xml:
            memberships.extend(parse_gpp_groups(decode_policy_file(xml)))
        return memberships

    def get_linked_containers(self):
        """
        Map each container that links a GPO to the GPO DNs it links, most
        specific link last. Covers the domain object and every OU; links on
        sites are not collected, since those live in the Configuration
        partition and apply by physical location rather than by OU.
        """
        links = {}
        domain_dn = self.addomain.domain_object.distinguishedname
        domain_entry = self.addc.ldap_get_single(domain_dn, ['gPLink'])
        if domain_entry is not None:
            linked = parse_gplink(ADUtils.get_entry_property(domain_entry, 'gPLink'))
            if linked:
                links[domain_dn.upper()] = linked

        for entry in self.addc.get_ous():
            dn = ADUtils.get_entry_property(entry, 'distinguishedName', '')
            linked = parse_gplink(ADUtils.get_entry_property(entry, 'gPLink'))
            if dn and linked:
                links[dn.upper()] = linked
        return links

    def get_computers_by_dn(self):
        """
        DN -> SID for every computer, used to find which computers sit inside a
        linked container. Uses the cache from computer enumeration when it is
        populated, and queries LDAP otherwise so this works in a DCOnly run.
        """
        computers = {}
        if self.addomain.computers:
            source = self.addomain.computers.values()
        else:
            source = self.addc.get_computers()
        for entry in source:
            dn = ADUtils.get_entry_property(entry, 'distinguishedName', '')
            sid = ADUtils.get_entry_property(entry, 'objectSid')
            if dn and sid:
                computers[dn.upper()] = sid
        return computers

    def enumerate_gpo_local_groups(self):
        """
        Run the GPOLocalGroup method. Results are stored on the AD object keyed
        by computer SID; the computer objects merge them in when they are
        written out.
        """
        logging.info('Collecting GPO local group membership from SYSVOL')

        links = self.get_linked_containers()
        if not links:
            logging.info('No GPO links found, nothing to collect for GPOLocalGroup')
            return

        self.smbconnection = self.connect_sysvol()
        if self.smbconnection is None:
            return

        # GPO DN -> file system path, so links can be followed to SYSVOL
        gpo_paths = {}
        for entry in self.addc.get_gpos():
            dn = ADUtils.get_entry_property(entry, 'distinguishedName', '')
            path = ADUtils.get_entry_property(entry, 'gPCFileSysPath')
            if dn and path:
                gpo_paths[dn.upper()] = path

        computers = self.get_computers_by_dn()
        # GPO DN -> memberships, so a GPO linked in several places is read once
        gpo_cache = {}
        found = 0

        for container_dn, gpo_dns in links.items():
            affected = [sid for dn, sid in computers.items()
                        if dn == container_dn or dn.endswith(',' + container_dn)]
            if not affected:
                continue
            for gpo_dn in gpo_dns:
                if gpo_dn not in gpo_cache:
                    path = gpo_paths.get(gpo_dn)
                    if not path:
                        logging.debug('Linked GPO %s has no file system path, skipping', gpo_dn)
                        gpo_cache[gpo_dn] = []
                    else:
                        gpo_cache[gpo_dn] = self.collect_gpo_memberships(path)
                memberships = gpo_cache[gpo_dn]
                if not memberships:
                    continue
                for group_key, identifier in memberships:
                    member = self.resolve_member(identifier)
                    if member is None:
                        continue
                    for computer_sid in affected:
                        entry = self.addomain.gpo_local_groups.setdefault(
                            computer_sid, {'admins': [], 'rdp': [], 'dcom': [], 'psremote': []})
                        if member not in entry[group_key]:
                            entry[group_key].append(member)
                            found += 1

        logging.info('Found %d GPO delivered local group memberships across %d computers',
                     found, len(self.addomain.gpo_local_groups))
