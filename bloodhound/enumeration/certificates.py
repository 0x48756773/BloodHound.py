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
Collection of Active Directory Certificate Services objects (the CertServices
collection method).

Everything here comes from LDAP in the Configuration naming context, so this
runs fine as part of a DCOnly collection. The registry half of AD CS collection
(CARegistry) is done per host by the computer enumerator instead.
"""
from __future__ import unicode_literals
import calendar
import logging
import queue
import threading

from bloodhound.ad.adcs import (
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
    CT_FLAG_NO_SECURITY_EXTENSION,
    CT_FLAG_PEND_ALL_REQUESTS,
    CT_FLAG_SUBJECT_ALT_REQUIRE_DNS,
    CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS,
    CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL,
    CT_FLAG_SUBJECT_ALT_REQUIRE_SPN,
    CT_FLAG_SUBJECT_ALT_REQUIRE_UPN,
    CT_FLAG_SUBJECT_REQUIRE_EMAIL,
    effective_ekus,
    filetime_to_span,
    has_flag,
    is_authentication_template,
    parse_certificate,
)
from bloodhound.ad.utils import ADUtils, AceResolver
from bloodhound.enumeration.acls import AclEnumerator, parse_binary_acl
from bloodhound.enumeration.outputworker import OutputWorker


class CertificateServicesEnumerator(object):
    """
    Enumerates the AD CS objects under CN=Public Key Services in the
    Configuration naming context and writes them to the BloodHound JSON files.
    """

    def __init__(self, addomain, addc, collect, disable_pooling):
        self.addomain = addomain
        self.addc = addc
        self.collect = collect
        self.disable_pooling = disable_pooling
        self.aclenumerator = AclEnumerator(addomain, addc, collect)
        self.aceresolver = AceResolver(addomain, addomain.objectresolver)
        self.result_q = None
        # Template displayName -> ObjectIdentifier, built while templates are
        # enumerated and used afterwards to resolve the template names a CA
        # publishes into the GUIDs BloodHound links against.
        self.template_guids = {}
        # Cache for DNS hostname -> computer SID lookups
        self.hostname_sids = {}
        # Whether the current output file has been closed off. Starts True
        # because there is no output file open yet.
        self.output_finalized = True

    def process_acldata(self, result):
        """
        Callback for the ACL worker pool, identical in shape to the one in the
        membership enumerator.
        """
        data, aces = result
        data['Aces'] += self.aceresolver.resolve_aces(aces)
        self.result_q.put(data)

    def start_writer(self, enumtype, filename):
        self.result_q = queue.Queue()
        self.output_finalized = False
        results_worker = threading.Thread(target=OutputWorker.membership_write_worker,
                                          args=(self.result_q, enumtype, filename))
        results_worker.daemon = True
        results_worker.start()
        return results_worker

    def finish(self, acl):
        """
        Shut down the ACL pool and close off the current output file.

        Idempotent, so it can also be called from a finally block after the
        normal path already ran: a second None on the queue would never be
        consumed and the join below would block forever.
        """
        if self.output_finalized:
            return
        self.output_finalized = True
        if acl and not self.disable_pooling and self.aclenumerator.pool is not None:
            try:
                self.aclenumerator.pool.close()
                self.aclenumerator.pool.join()
            except Exception as exc:
                logging.debug('Error while shutting down the ACL pool: %s', exc)
        self.result_q.put(None)
        self.result_q.join()

    def run_step(self, step, *args, **kwargs):
        """
        Run one enumeration step, making sure its output file is closed off
        even when the step raises.
        """
        try:
            step(*args, **kwargs)
        finally:
            self.finish('acl' in self.collect)

    def queue_object(self, data, entrytype, entry, acl):
        """
        Either hand the object to the ACL pool (which puts it on the result
        queue when it is done) or write it out directly.
        """
        if not acl:
            self.result_q.put(data)
            return
        sd = ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True)
        if self.disable_pooling:
            self.process_acldata(parse_binary_acl(data, entrytype, sd, self.addc.objecttype_guid_map))
        else:
            self.aclenumerator.pool.apply_async(parse_binary_acl,
                                                args=(data, entrytype, sd, self.addc.objecttype_guid_map),
                                                callback=self.process_acldata)

    @staticmethod
    def get_guid(entry, description):
        """
        objectGUID comes back from ldap3 formatted as {guid}; BloodHound wants
        it bare and uppercase.
        """
        try:
            return entry['attributes']['objectGUID'][1:-1].upper()
        except KeyError:
            logging.warning('Could not determine GUID for %s %s', description,
                            ADUtils.get_entry_property(entry, 'distinguishedName'))
            return None

    def base_properties(self, entry, with_properties, name=None):
        """
        The properties every AD CS object carries. The name is qualified with
        the domain, matching how BloodHound names other objects.
        """
        if name is None:
            name = ADUtils.get_entry_property(entry, 'name', '')
        props = {
            'domain': self.addomain.domain.upper(),
            'name': '%s@%s' % (name.upper(), self.addomain.domain.upper()),
            'distinguishedname': ADUtils.get_entry_property(entry, 'distinguishedName', '').upper(),
            'domainsid': self.addomain.domain_object.sid,
            'highvalue': False,
        }
        if with_properties:
            props['description'] = ADUtils.get_entry_property(entry, 'description')
            whencreated = ADUtils.get_entry_property(entry, 'whencreated', default=0)
            if not isinstance(whencreated, int):
                whencreated = calendar.timegm(whencreated.timetuple())
            props['whencreated'] = whencreated
        return props

    def add_certificate_properties(self, props, entry):
        """
        Decode the cACertificate attribute onto the given properties dict.
        Multi-valued in the schema, but the CA objects BloodHound cares about
        publish a single current certificate.
        """
        certificates = ADUtils.get_entry_property(entry, 'cACertificate', [], raw=True)
        if isinstance(certificates, (bytes, bytearray)):
            certificates = [certificates]
        certificate = certificates[0] if certificates else None
        parsed = parse_certificate(certificate)
        props['certthumbprint'] = parsed['thumbprint']
        # The certificate's own subject, falling back to the directory object's
        # name when the certificate could not be parsed
        props['certname'] = parsed['name'] or ADUtils.get_entry_property(entry, 'name')
        # Only this certificate's own thumbprint: assembling the full chain
        # needs the issuing CAs, which BloodHound resolves from the other CA
        # objects once they are all ingested.
        props['certchain'] = parsed['chain']
        props['hasbasicconstraints'] = parsed['hasbasicconstraints']
        props['basicconstraintpathlength'] = parsed['basicconstraintpathlength']
        return parsed

    def resolve_hosting_computer(self, dnshostname):
        """
        Map a CA's dNSHostName to the SID of the computer object hosting it.

        During a full collection the computer cache already has this. During a
        DCOnly collection it does not, so fall back to a targeted LDAP lookup
        rather than reporting the CA as unhosted.
        """
        if not dnshostname:
            return None
        key = dnshostname.lower()
        if key in self.hostname_sids:
            return self.hostname_sids[key]
        try:
            sid = self.addomain.computersidcache.get(key)
            self.hostname_sids[key] = sid
            return sid
        except KeyError:
            pass
        sid = None
        try:
            entries = self.addc.search('(&(sAMAccountType=805306369)(dNSHostName=%s))' % dnshostname,
                                       ['objectSid'],
                                       generator=False)
            for computer in entries:
                sid = ADUtils.get_entry_property(computer, 'objectSid')
                break
        except Exception as exc:
            logging.debug('Could not resolve CA host %s: %s', dnshostname, exc)
        if sid is None:
            logging.debug('Could not resolve the computer hosting CA %s', dnshostname)
        self.hostname_sids[key] = sid
        return sid

    def enumerate_cert_templates(self, timestamp=''):
        filename = timestamp + 'certtemplates.json'
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        entries = self.addc.get_cert_templates(include_properties=with_properties, acl=acl)

        logging.debug('Writing certificate templates to file: %s', filename)
        self.start_writer('certtemplates', filename)
        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()

        for entry in entries:
            guid = self.get_guid(entry, 'certificate template')
            if guid is None:
                continue

            name_flag = ADUtils.get_entry_property(entry, 'msPKI-Certificate-Name-Flag', 0)
            enrollment_flag = ADUtils.get_entry_property(entry, 'msPKI-Enrollment-Flag', 0)
            ekus = ADUtils.get_entry_property(entry, 'pKIExtendedKeyUsage', [])
            application_policies = ADUtils.get_entry_property(entry, 'msPKI-Certificate-Application-Policy', [])
            effective = effective_ekus(ekus, application_policies)

            # Templates are known by their display name in the CA console and
            # in every write-up, so name the object after that rather than the
            # CN, which is often a run-together version of it
            displayname = ADUtils.get_entry_property(entry, 'displayName')
            props = self.base_properties(entry, with_properties,
                                         name=displayname or ADUtils.get_entry_property(entry, 'name', ''))
            props.update({
                'displayname': displayname,
                'validityperiod': filetime_to_span(
                    ADUtils.get_entry_property(entry, 'pKIExpirationPeriod', raw=True)),
                'renewalperiod': filetime_to_span(
                    ADUtils.get_entry_property(entry, 'pKIOverlapPeriod', raw=True)),
                'schemaversion': ADUtils.get_entry_property(entry, 'msPKI-Template-Schema-Version', 1),
                'oid': ADUtils.get_entry_property(entry, 'msPKI-Cert-Template-OID'),
                'enrollmentflag': enrollment_flag,
                'requiresmanagerapproval': has_flag(enrollment_flag, CT_FLAG_PEND_ALL_REQUESTS),
                'nosecurityextension': has_flag(enrollment_flag, CT_FLAG_NO_SECURITY_EXTENSION),
                'certificatenameflag': name_flag,
                'enrolleesuppliessubject': has_flag(name_flag, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
                'subjectaltrequireupn': has_flag(name_flag, CT_FLAG_SUBJECT_ALT_REQUIRE_UPN),
                'subjectaltrequiredns': has_flag(name_flag, CT_FLAG_SUBJECT_ALT_REQUIRE_DNS),
                'subjectaltrequiredomaindns': has_flag(name_flag, CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS),
                'subjectaltrequireemail': has_flag(name_flag, CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL),
                'subjectaltrequirespn': has_flag(name_flag, CT_FLAG_SUBJECT_ALT_REQUIRE_SPN),
                'subjectrequireemail': has_flag(name_flag, CT_FLAG_SUBJECT_REQUIRE_EMAIL),
                'ekus': list(ekus),
                'certificateapplicationpolicy': list(application_policies),
                'effectiveekus': effective,
                'applicationpolicies': ADUtils.get_entry_property(entry, 'msPKI-RA-Application-Policies', []),
                'authorizedsignatures': ADUtils.get_entry_property(entry, 'msPKI-RA-Signature', 0),
                'authenticationenabled': is_authentication_template(effective),
                'schannelauthenticationenabled': is_authentication_template(effective, schannel=True),
            })

            template = {
                'ObjectIdentifier': guid,
                'Properties': props,
                'Aces': [],
                'IsDeleted': False,
                'IsACLProtected': False,
            }

            # CAs publish templates by name, so remember both the CN and the
            # display name - which of the two appears in certificateTemplates
            # depends on the template's schema version.
            for key in (ADUtils.get_entry_property(entry, 'name'),
                        ADUtils.get_entry_property(entry, 'displayName')):
                if key:
                    self.template_guids[key.lower()] = guid

            self.addomain.dncache[props['distinguishedname']] = {
                'ObjectIdentifier': guid,
                'ObjectType': 'CertTemplate',
            }

            self.queue_object(template, 'certtemplate', entry, acl)

        self.finish(acl)
        logging.debug('Finished writing certificate templates')

    def enumerate_enterprise_cas(self, timestamp=''):
        filename = timestamp + 'enterprisecas.json'
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        entries = self.addc.get_enterprise_cas(include_properties=with_properties, acl=acl)

        logging.debug('Writing enterprise CAs to file: %s', filename)
        self.start_writer('enterprisecas', filename)
        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()

        for entry in entries:
            guid = self.get_guid(entry, 'enterprise CA')
            if guid is None:
                continue

            caname = ADUtils.get_entry_property(entry, 'name', '')
            dnshostname = ADUtils.get_entry_property(entry, 'dNSHostName')

            props = self.base_properties(entry, with_properties)
            props['caname'] = caname
            props['dnshostname'] = dnshostname
            props['flags'] = ADUtils.get_entry_property(entry, 'flags', 0)
            self.add_certificate_properties(props, entry)

            published = ADUtils.get_entry_property(entry, 'certificateTemplates', [])
            if isinstance(published, str):
                published = [published]
            enabled = []
            unresolved = []
            for template_name in published:
                template_guid = self.template_guids.get(template_name.lower())
                if template_guid:
                    enabled.append({'ObjectIdentifier': template_guid, 'ObjectType': 'CertTemplate'})
                else:
                    # A template can be published by a CA but deleted from the
                    # directory, or be a template we could not read.
                    unresolved.append(template_name)
            props['unresolvedpublishedtemplates'] = unresolved

            enterpriseca = {
                'ObjectIdentifier': guid,
                'Properties': props,
                'HostingComputer': self.resolve_hosting_computer(dnshostname),
                'EnabledCertTemplates': enabled,
                # Gathered by the CARegistry method during computer enumeration,
                # which is why that has to run before this. Null means the
                # method was not selected or the host was never reached.
                'CARegistryData': self.addomain.ca_registry_data.get(guid),
                'Aces': [],
                'IsDeleted': False,
                'IsACLProtected': False,
            }

            self.addomain.dncache[props['distinguishedname']] = {
                'ObjectIdentifier': guid,
                'ObjectType': 'EnterpriseCA',
            }

            self.queue_object(enterpriseca, 'enterpriseca', entry, acl)

        self.finish(acl)
        logging.debug('Finished writing enterprise CAs')

    def enumerate_ca_store(self, getter, enumtype, entrytype, filename_base, timestamp=''):
        """
        Root CAs, AIA CAs and the NTAuth store are all certificationAuthority
        objects that differ only in which container they live in and which
        extra attributes matter, so they share one enumeration routine.
        """
        filename = timestamp + filename_base
        with_properties = 'objectprops' in self.collect
        acl = 'acl' in self.collect
        entries = getter(include_properties=with_properties, acl=acl)

        logging.debug('Writing %s to file: %s', enumtype, filename)
        self.start_writer(enumtype, filename)
        if acl and not self.disable_pooling:
            self.aclenumerator.init_pool()

        for entry in entries:
            guid = self.get_guid(entry, enumtype)
            if guid is None:
                continue

            props = self.base_properties(entry, with_properties)
            data = {
                'ObjectIdentifier': guid,
                'Properties': props,
                'DomainSID': self.addomain.domain_object.sid,
                'Aces': [],
                'IsDeleted': False,
                'IsACLProtected': False,
            }

            if entrytype == 'ntauthstore':
                # The NTAuth store is a list of certificates rather than one
                # certificate, and BloodHound keys on their thumbprints.
                certificates = ADUtils.get_entry_property(entry, 'cACertificate', [], raw=True)
                if isinstance(certificates, (bytes, bytearray)):
                    certificates = [certificates]
                thumbprints = []
                for certificate in certificates:
                    parsed = parse_certificate(certificate)
                    if parsed['thumbprint']:
                        thumbprints.append(parsed['thumbprint'])
                data['CertThumbprints'] = thumbprints
            else:
                self.add_certificate_properties(props, entry)

            if entrytype == 'aiaca':
                crosspair = ADUtils.get_entry_property(entry, 'crossCertificatePair', [], raw=True)
                if isinstance(crosspair, (bytes, bytearray)):
                    crosspair = [crosspair]
                props['hascrosscertificatepair'] = len(crosspair) > 0
                props['crosscertificatepair'] = [
                    thumb for thumb in (parse_certificate(pair)['thumbprint'] for pair in crosspair) if thumb
                ]

            self.addomain.dncache[props['distinguishedname']] = {
                'ObjectIdentifier': guid,
                'ObjectType': {'rootca': 'RootCA', 'aiaca': 'AIACA', 'ntauthstore': 'NTAuthStore'}[entrytype],
            }

            self.queue_object(data, entrytype, entry, acl)

        self.finish(acl)
        logging.debug('Finished writing %s', enumtype)

    def prefetch_ca_hosts(self):
        """
        Record which enterprise CAs run on which host, without writing anything.

        The CARegistry method needs this before computer enumeration starts, so
        it cannot wait for the full CertServices run - that happens afterwards,
        so it can include the registry data it collects.
        """
        if not self.addc.get_pki_services_dn():
            logging.warning('Could not locate the Public Key Services container, skipping CARegistry')
            return
        count = 0
        for entry in self.addc.get_enterprise_cas():
            guid = self.get_guid(entry, 'enterprise CA')
            dnshostname = ADUtils.get_entry_property(entry, 'dNSHostName')
            if guid is None or not dnshostname:
                continue
            self.addomain.enterprise_cas.setdefault(dnshostname.lower(), []).append({
                'name': ADUtils.get_entry_property(entry, 'name', ''),
                'objectidentifier': guid,
            })
            count += 1
        logging.info('Found %d enterprise CA(s) to query the registry of', count)

    def enumerate_certificate_services(self, timestamp=''):
        """
        Run the whole CertServices method. Templates go first because the
        enterprise CA objects reference them by name and need the GUID map.
        """
        if not self.addc.get_pki_services_dn():
            logging.warning('Could not locate the Public Key Services container, skipping CertServices')
            return
        logging.info('Collecting AD CS objects')
        self.run_step(self.enumerate_cert_templates, timestamp)
        self.run_step(self.enumerate_enterprise_cas, timestamp)
        self.run_step(self.enumerate_ca_store, self.addc.get_root_cas, 'rootcas', 'rootca', 'rootcas.json', timestamp)
        self.run_step(self.enumerate_ca_store, self.addc.get_aia_cas, 'aiacas', 'aiaca', 'aiacas.json', timestamp)
        self.run_step(self.enumerate_ca_store, self.addc.get_ntauth_stores, 'ntauthstores', 'ntauthstore', 'ntauthstores.json', timestamp)
