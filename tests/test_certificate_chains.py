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
Tests for assembling the CA hierarchy from the collected certificates.

BloodHound builds its IssuedSignedBy edges from each CA's certchain, and the
certificate escalation paths require an issuing CA to reach a root CA that is
trusted for the domain. A chain holding only the CA's own thumbprint leaves
every issuing CA disconnected from its root, which silently costs every ESC
path through it - so these run against real generated certificates rather
than hand-written structures.
"""
import datetime
import logging
import unittest

from bloodhound.ad.adcs import (
    certificate_identity,
    certificate_thumbprint,
    parse_certificate,
    select_current_certificate,
)
from bloodhound.enumeration.certificates import CertificateServicesEnumerator

logging.disable(logging.CRITICAL)

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False


def make_certificate(common_name, issuer_name=None, issuer_key=None, years=10):
    """
    Build a DER encoded CA certificate. Self-signed when no issuer is given.
    Elliptic curve keys purely because they are quick to generate.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    start = datetime.datetime(2020, 1, 1)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key or key, hashes.SHA256()))
    return certificate.public_bytes(serialization.Encoding.DER), subject, key


def build_enumerator(certificates):
    """
    An enumerator with just the certificate index populated, as
    prefetch_ca_certificates would leave it.
    """
    enumerator = CertificateServicesEnumerator.__new__(CertificateServicesEnumerator)
    enumerator.ca_certificates = {}
    enumerator.ca_subjects = {}
    for der in certificates:
        identity = certificate_identity(der)
        enumerator.ca_certificates[identity['thumbprint']] = identity
        enumerator.ca_subjects.setdefault(identity['subject'], identity['thumbprint'])
    return enumerator


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, 'cryptography is required to build test certificates')
class TestCertificateChain(unittest.TestCase):
    def setUp(self):
        self.root, root_subject, root_key = make_certificate('Root-CA')
        self.issuing, issuing_subject, issuing_key = make_certificate(
            'Issuing-CA', root_subject, root_key)
        # A third tier, to check the walk does not stop after one hop
        self.sub_issuing, _, _ = make_certificate(
            'Sub-Issuing-CA', issuing_subject, issuing_key)
        self.root_tp = certificate_thumbprint(self.root)
        self.issuing_tp = certificate_thumbprint(self.issuing)
        self.sub_tp = certificate_thumbprint(self.sub_issuing)

    def test_self_signed_root_chains_to_itself(self):
        enumerator = build_enumerator([self.root])
        self.assertEqual(enumerator.build_certificate_chain(self.root_tp), [self.root_tp])

    def test_issuing_ca_chain_reaches_its_root(self):
        enumerator = build_enumerator([self.root, self.issuing])
        chain = enumerator.build_certificate_chain(self.issuing_tp)
        self.assertEqual(chain, [self.issuing_tp, self.root_tp],
                         'the chain must start at the CA itself and end at the root')

    def test_chain_walks_more_than_one_level(self):
        enumerator = build_enumerator([self.root, self.issuing, self.sub_issuing])
        self.assertEqual(enumerator.build_certificate_chain(self.sub_tp),
                         [self.sub_tp, self.issuing_tp, self.root_tp])

    def test_chain_stops_when_the_issuer_was_not_collected(self):
        # Only the issuing CA is known; its root is outside what we could read
        enumerator = build_enumerator([self.issuing])
        self.assertEqual(enumerator.build_certificate_chain(self.issuing_tp), [self.issuing_tp])

    def test_unknown_thumbprint_chains_to_itself(self):
        enumerator = build_enumerator([self.root])
        self.assertEqual(enumerator.build_certificate_chain('NOTATHUMBPRINT'),
                         ['NOTATHUMBPRINT'])

    def test_missing_thumbprint_gives_an_empty_chain(self):
        enumerator = build_enumerator([self.root])
        self.assertEqual(enumerator.build_certificate_chain(None), [])

    def test_a_loop_does_not_hang(self):
        # Two certificates each naming the other as issuer, which a cross
        # signed pair can look like
        enumerator = build_enumerator([])
        enumerator.ca_certificates = {
            'AA': {'thumbprint': 'AA', 'subject': 'CN=A', 'issuer': 'CN=B'},
            'BB': {'thumbprint': 'BB', 'subject': 'CN=B', 'issuer': 'CN=A'},
        }
        enumerator.ca_subjects = {'CN=A': 'AA', 'CN=B': 'BB'}
        self.assertEqual(enumerator.build_certificate_chain('AA'), ['AA', 'BB'])

    def test_several_cas_sharing_a_root(self):
        other, _, _ = make_certificate('Other-Issuing-CA',
                                       *make_certificate('Root-CA')[1:])
        enumerator = build_enumerator([self.root, self.issuing, other])
        # The known issuing CA still resolves correctly alongside an unrelated one
        self.assertEqual(enumerator.build_certificate_chain(self.issuing_tp),
                         [self.issuing_tp, self.root_tp])


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, 'cryptography is required to build test certificates')
class TestCurrentCertificateSelection(unittest.TestCase):
    def test_renewed_ca_uses_the_certificate_that_expires_last(self):
        """
        A renewed CA keeps its superseded certificates on the object. The
        thumbprint has to be the current one or it will not match the NTAuth
        store, which takes down every certificate path through the CA.
        """
        root, subject, key = make_certificate('Root-CA')
        old, _, _ = make_certificate('Issuing-CA', subject, key, years=5)
        new, _, _ = make_certificate('Issuing-CA', subject, key, years=20)

        # Whichever order the directory returns them in
        for candidates in ([old, new], [new, old]):
            chosen = select_current_certificate(candidates)
            self.assertEqual(certificate_thumbprint(chosen), certificate_thumbprint(new))

    def test_single_certificate_is_returned_as_is(self):
        root, _, _ = make_certificate('Root-CA')
        self.assertIs(select_current_certificate([root]), root)

    def test_no_certificates(self):
        self.assertIsNone(select_current_certificate([]))
        self.assertIsNone(select_current_certificate(None))

    def test_unparseable_certificates_fall_back_to_the_first(self):
        # No basis to choose, so behave as before rather than dropping the CA
        self.assertEqual(select_current_certificate([b'garbage', b'alsogarbage']), b'garbage')

    def test_identity_and_parse_agree_on_subject_and_issuer(self):
        root, subject, key = make_certificate('Root-CA')
        issuing, _, _ = make_certificate('Issuing-CA', subject, key)
        identity = certificate_identity(issuing)
        parsed = parse_certificate(issuing)
        self.assertEqual(identity['subject'], parsed['subject'])
        self.assertEqual(identity['issuer'], parsed['issuer'])
        self.assertEqual(identity['issuer'], certificate_identity(root)['subject'],
                         'the issuer must match the root subject exactly, or no chain is built')


if __name__ == '__main__':
    unittest.main()


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, 'cryptography is required to build test certificates')
class TestCertificatePropertiesUseTheChain(unittest.TestCase):
    """
    The chain builder and the current-certificate pick are only worth anything
    if the emitted properties actually go through them. Testing the helpers
    alone would miss exactly the kind of unwired fix that caused the empty
    certchain in the first place.
    """
    def setUp(self):
        self.root, root_subject, root_key = make_certificate('Root-CA')
        self.issuing_old, _, _ = make_certificate('Issuing-CA', root_subject, root_key, years=5)
        self.issuing_new, _, _ = make_certificate('Issuing-CA', root_subject, root_key, years=20)
        self.enumerator = build_enumerator([self.root, self.issuing_old, self.issuing_new])

    def entry(self, certificates, name='Issuing-CA'):
        return {
            'attributes': {'name': name, 'cACertificate': list(certificates)},
            'raw_attributes': {'cACertificate': list(certificates)},
        }

    def test_emitted_chain_reaches_the_root(self):
        props = {}
        self.enumerator.add_certificate_properties(props, self.entry([self.issuing_new]))

        self.assertEqual(props['certthumbprint'], certificate_thumbprint(self.issuing_new))
        self.assertEqual(props['certchain'],
                         [certificate_thumbprint(self.issuing_new),
                          certificate_thumbprint(self.root)],
                         'certchain must be emitted via the chain builder, not the bare thumbprint')

    def test_emitted_thumbprint_is_the_current_certificate(self):
        props = {}
        # Directory order puts the superseded certificate first
        self.enumerator.add_certificate_properties(
            props, self.entry([self.issuing_old, self.issuing_new]))
        self.assertEqual(props['certthumbprint'], certificate_thumbprint(self.issuing_new),
                         'a renewed CA must report its current certificate')

    def test_self_signed_root_still_reports_itself(self):
        props = {}
        self.enumerator.add_certificate_properties(props, self.entry([self.root], name='Root-CA'))
        self.assertEqual(props['certchain'], [certificate_thumbprint(self.root)])

    def test_a_ca_with_no_certificate_is_not_fatal(self):
        props = {}
        self.enumerator.add_certificate_properties(props, self.entry([], name='Broken-CA'))
        self.assertIsNone(props['certthumbprint'])
        self.assertEqual(props['certchain'], [])
        # Falls back to the directory object's name
        self.assertEqual(props['certname'], 'Broken-CA')

    def test_basic_constraints_come_through(self):
        props = {}
        self.enumerator.add_certificate_properties(props, self.entry([self.root], name='Root-CA'))
        self.assertTrue(props['hasbasicconstraints'])
