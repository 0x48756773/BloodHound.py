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
Helpers for Active Directory Certificate Services (AD CS) collection.

Everything in here is deliberately free of network or LDAP state so it can be
unit tested without a domain: flag decoding, certificate parsing and the
validity/renewal period conversions used by the CertServices collection method.
"""
import hashlib
import logging
import struct

# msPKI-Certificate-Name-Flag
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 0x00800000
CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x02000000
CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x08000000
CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x20000000
CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000

# msPKI-Enrollment-Flag
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000

# Enterprise CA "EditFlags" registry value. When this bit is set the CA honours
# a subject alternative name supplied by the requester on *any* template, which
# is what turns an otherwise harmless template into an escalation path.
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

# Extended Key Usage OIDs that matter for authentication.
EKU_ANY_PURPOSE = '2.5.29.37.0'
EKU_CLIENT_AUTHENTICATION = '1.3.6.1.5.5.7.3.2'
EKU_PKINIT_CLIENT_AUTHENTICATION = '1.3.6.1.5.2.3.4'
EKU_SMART_CARD_LOGON = '1.3.6.1.4.1.311.20.2.2'
EKU_CERTIFICATE_REQUEST_AGENT = '1.3.6.1.4.1.311.20.2.1'

# EKUs that allow a certificate to be used for Kerberos (PKINIT) authentication.
AUTHENTICATION_EKUS = (
    EKU_CLIENT_AUTHENTICATION,
    EKU_PKINIT_CLIENT_AUTHENTICATION,
    EKU_SMART_CARD_LOGON,
    EKU_ANY_PURPOSE,
)

# EKUs that allow a certificate to be used for Schannel (LDAPS/TLS) authentication.
# PKINIT and Smart Card Logon do not apply to Schannel, hence the separate tuple.
SCHANNEL_AUTHENTICATION_EKUS = (
    EKU_CLIENT_AUTHENTICATION,
    EKU_ANY_PURPOSE,
)


def has_flag(value, flag):
    """
    Test a single bit in an msPKI flag attribute. Missing attributes come back
    from LDAP as None, which is not the same as 0 but behaves the same here.
    """
    if not value:
        return False
    return int(value) & flag == flag


def filetime_to_span(value):
    """
    Convert an msPKI validity/renewal period to a human readable span.

    The attribute is a little-endian 8 byte *negative* FILETIME delta (100ns
    units). BloodHound shows these as strings like "1 year" or "6 weeks", so we
    reduce to the largest unit that divides evenly rather than printing seconds.
    """
    if not value:
        return None
    if isinstance(value, int):
        # Already converted by the LDAP library
        raw = value
    else:
        try:
            raw = struct.unpack('<q', bytes(value[:8]))[0]
        except (struct.error, TypeError, ValueError):
            logging.debug('Could not unpack validity period: %r', value)
            return None

    # Stored as a negative offset from "now"
    seconds = abs(raw) // 10000000
    if seconds == 0:
        return None

    # Ordered largest first so we report the coarsest unit that fits exactly.
    # The year/month values are the ones the Windows CA UI uses.
    for unit, length in (('year', 31536000), ('month', 2592000),
                         ('week', 604800), ('day', 86400), ('hour', 3600)):
        if seconds % length == 0:
            count = seconds // length
            return '%d %s%s' % (count, unit, '' if count == 1 else 's')
    return '%d seconds' % seconds


def certificate_thumbprint(certdata):
    """
    SHA1 thumbprint of a DER encoded certificate, uppercase hex.
    This is the identifier BloodHound uses to tie CA objects together, so it is
    computed directly from the bytes rather than via an X.509 parser.
    """
    if not certdata:
        return None
    return hashlib.sha1(bytes(certdata)).hexdigest().upper()


def parse_certificate(certdata):
    """
    Pull the fields BloodHound wants out of a DER encoded certificate.

    Returns a dict with thumbprint, name, chain, basic constraint info. Parsing
    beyond the thumbprint needs an X.509 parser; if `cryptography` is not
    available we still return the thumbprint since that is what the graph keys
    on, and leave the rest empty rather than failing the whole collection.
    """
    result = {
        'thumbprint': certificate_thumbprint(certdata),
        'name': None,
        'chain': [],
        'hasbasicconstraints': False,
        'basicconstraintpathlength': 0,
    }
    if not certdata:
        return result

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtensionOID
    except ImportError:
        logging.debug('cryptography is not installed, only reporting certificate thumbprints')
        return result

    try:
        cert = x509.load_der_x509_certificate(bytes(certdata))
    except Exception as exc:
        logging.debug('Could not parse certificate: %s', exc)
        return result

    try:
        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if common_names:
            result['name'] = common_names[0].value
    except Exception as exc:
        logging.debug('Could not read certificate subject: %s', exc)

    # A self signed CA certificate is its own chain; anything longer has to be
    # assembled from the other CA objects, which BloodHound does server side.
    if result['thumbprint']:
        result['chain'] = [result['thumbprint']]

    try:
        basic = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        result['hasbasicconstraints'] = bool(basic.ca)
        result['basicconstraintpathlength'] = basic.path_length or 0
    except x509.ExtensionNotFound:
        pass
    except Exception as exc:
        logging.debug('Could not read basic constraints: %s', exc)

    return result


def effective_ekus(ekus, application_policies):
    """
    Which EKUs actually apply to a certificate issued from a template.

    Schema version 1 templates have no application policies, so pKIExtendedKeyUsage
    is what gets issued. From schema version 2 onwards the application policies
    extension wins when present, and the plain EKU list is only a fallback.
    """
    if application_policies:
        return list(application_policies)
    return list(ekus or [])


def is_authentication_template(effective, schannel=False):
    """
    Whether a certificate from this template can be used to authenticate.

    An empty EKU list means the certificate is valid for any purpose, which
    includes authentication - that is why the empty case returns True rather
    than False.
    """
    if not effective:
        return True
    wanted = SCHANNEL_AUTHENTICATION_EKUS if schannel else AUTHENTICATION_EKUS
    return any(eku in wanted for eku in effective)
