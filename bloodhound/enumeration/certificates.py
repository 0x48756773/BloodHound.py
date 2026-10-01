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
    certificate_identity,
    effective_ekus,
    filetime_to_span,
    has_flag,
    is_authentication_template,
    parse_certificate,
    select_current_certificate,
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
        # Lowercased names of every template published by at least one
        # enterprise CA. A template that no CA publishes cannot be enrolled
        # from, which is what BloodHound's 'enabled' property means, so this
        # has to be known before the templates themselves are written out.
        self.published_templates = set()
        # CA certificates indexed for chain building: thumbprint -> identity,
        # and subject -> thumbprint so an issuer can be looked up
        self.ca_certificates = {}
        self.ca_subjects = {}
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

    @staticmethod
    def certificates_of(entry):
        """
        The cACertificate values of a CA object, always as a list. A renewed CA
        keeps its superseded certificates here.
        """
        certificates = ADUtils.get_entry_property(entry, 'cACertificate', [], raw=True)
        if isinstance(certificates, (bytes, bytearray)):
            certificates = [certificates]
        return [certificate for certificate in certificates if certificate]

    def prefetch_ca_certificates(self):
        """
        Read every CA certificate in the forest once and index it by subject.

        A certificate's issuer is the subject of the certificate above it, so
        this index is what lets each CA's chain be followed up to its root.
        BloodHound builds the IssuedSignedBy edges from those chains, and the
        ESC paths require an issuing CA to reach a root CA that is trusted for
        the domain - so a chain holding only the CA's own thumbprint leaves
        every issuing CA disconnected from its root.
        """
        getters = (self.addc.get_enterprise_cas, self.addc.get_root_cas, self.addc.get_aia_cas)
        for getter in getters:
            try:
                entries = getter()
            except Exception as exc:
                logging.debug('Could not read CA objects for the certificate chain: %s', exc)
                continue
            for entry in entries:
                for certificate in self.certificates_of(entry):
                    identity = certificate_identity(certificate)
                    thumbprint = identity['thumbprint']
                    if not thumbprint or not identity['subject']:
                        continue
                    self.ca_certificates[thumbprint] = identity
                    # Several CA objects publish the same certificate, and a
                    # renewed CA has more than one with the same subject. Keep
                    # the first; which of the duplicates we index does not
                    # matter since they share a subject.
                    self.ca_subjects.setdefault(identity['subject'], thumbprint)
        logging.debug('Indexed %d CA certificate(s) for chain building', len(self.ca_certificates))

    def build_certificate_chain(self, thumbprint):
        """
        Walk from a certificate up to its root, returning the thumbprints from
        the certificate itself outwards.

        Stops at a self-signed certificate, at one whose issuer we have no
        certificate for, and on a loop - a cross-signed set can otherwise
        chain back on itself.
        """
        if not thumbprint:
            return []
        chain = [thumbprint]
        seen = {thumbprint}
        current = self.ca_certificates.get(thumbprint)
        while current:
            subject, issuer = current['subject'], current['issuer']
            if not issuer or issuer == subject:
                # Self-signed, so this is the root and the chain ends here
                break
            parent = self.ca_subjects.get(issuer)
            if not parent or parent in seen:
                break
            chain.append(parent)
            seen.add(parent)
            current = self.ca_certificates.get(parent)
        return chain

    def add_certificate_properties(self, props, entry):
        """
        Decode the cACertificate attribute onto the given properties dict.
        """
        certificate = select_current_certificate(self.certificates_of(entry))
        parsed = parse_certificate(certificate)
        props['certthumbprint'] = parsed['thumbprint']
        # The certificate's own subject, falling back to the directory object's
        # name when the certificate could not be parsed
        props['certname'] = parsed['name'] or ADUtils.get_entry_property(entry, 'name')
        # The chain up to the root, when the other CA certificates have been
        # indexed. Falls back to this certificate alone, which is correct for a
        # self-signed root and all we can say for anything else.
        chain = self.build_certificate_chain(parsed['thumbprint'])
        props['certchain'] = chain or parsed['chain']
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
            # A CA can publish a template under either its CN or its display
            # name depending on the template's schema version, so match on both
            cn = ADUtils.get_entry_property(entry, 'name', '')
            props.update({
                'enabled': any(candidate and candidate.lower() in self.published_templates
                               for candidate in (cn, displayname)),
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
                # Links the CA to its domain. The root CA and NTAuth store
                # objects carry this too; without it the CA is not tied to the
                # domain it issues for.
                'DomainSID': self.addomain.domain_object.sid,
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
                # BloodHound matches an enterprise CA's certthumbprint against
                # this list to decide whether the CA is trusted for NT
                # authentication, and every certificate escalation path runs
                # through that trust. It reads it as a node property, so the
                # top-level copy alone is not enough.
                props['certthumbprints'] = thumbprints
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

    def prefetch_published_templates(self):
        """
        Record which templates the enterprise CAs publish.

        BloodHound treats a template as enabled when a CA offers it for
        enrollment, and will not consider a disabled one for any of the
        certificate escalation paths. The CA objects are written after the
        templates - they reference templates by name and need the GUID map -
        so this reads just the certificateTemplates attribute up front.
        """
        for entry in self.addc.get_enterprise_cas():
            published = ADUtils.get_entry_property(entry, 'certificateTemplates', [])
            if isinstance(published, str):
                published = [published]
            for name in published:
                if name:
                    self.published_templates.add(name.lower())
        logging.debug('Found %d distinct published certificate template name(s)',
                      len(self.published_templates))

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
        # Which templates the CAs publish decides the enabled flag on each
        # template, so this has to happen before they are written
        self.prefetch_published_templates()
        # The CA certificates have to be indexed before any of them is written,
        # since each one's chain is built by following issuers across the set
        self.prefetch_ca_certificates()
        self.run_step(self.enumerate_cert_templates, timestamp)
        self.run_step(self.enumerate_enterprise_cas, timestamp)
        self.run_step(self.enumerate_ca_store, self.addc.get_root_cas, 'rootcas', 'rootca', 'rootcas.json', timestamp)
        self.run_step(self.enumerate_ca_store, self.addc.get_aia_cas, 'aiacas', 'aiaca', 'aiacas.json', timestamp)
        self.run_step(self.enumerate_ca_store, self.addc.get_ntauth_stores, 'ntauthstores', 'ntauthstore', 'ntauthstores.json', timestamp)
