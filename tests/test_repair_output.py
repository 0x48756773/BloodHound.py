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
Tests for repair_output.py, which rewrites the bare strings older collections
put in AllowedToDelegate into the objects BloodHound expects.

The files this runs against are the only copy of a collection that may have
taken an hour, so the cases that matter most here are the ones where it must
not destroy anything: unrelated fields, the meta block, files it does not
understand, and running it twice.
"""
import json
import logging
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import repair_output

logging.disable(logging.CRITICAL)


def broken_document():
    """
    A users.json as the affected versions wrote it: AllowedToDelegate holding
    bare strings, which is what BloodHound rejects.
    """
    return {
        'data': [
            {
                'ObjectIdentifier': 'S-1-5-21-1-2-3-1105',
                'AllowedToDelegate': ['S-1-5-21-1-2-3-2001', 'SERVER2.CORP.LOCAL'],
                'HasSIDHistory': [],
                'PrimaryGroupSID': 'S-1-5-21-1-2-3-513',
                'Properties': {'name': 'ALICE@CORP.LOCAL',
                               'allowedtodelegate': ['HOST/server2.corp.local']},
                'Aces': [],
            },
            {
                'ObjectIdentifier': 'S-1-5-21-1-2-3-1106',
                'AllowedToDelegate': [],
                'Properties': {'name': 'BOB@CORP.LOCAL'},
                'Aces': [],
            },
        ],
        'meta': {'methods': 0, 'type': 'users', 'count': 2, 'version': 5},
    }


class TestRepairInMemory(unittest.TestCase):
    def test_strings_become_typed_principals(self):
        document = broken_document()
        fixed = repair_output.repair_document(document)

        self.assertEqual(fixed, 2)
        self.assertEqual(document['data'][0]['AllowedToDelegate'], [
            {'ObjectIdentifier': 'S-1-5-21-1-2-3-2001', 'ObjectType': 'Computer'},
            {'ObjectIdentifier': 'SERVER2.CORP.LOCAL', 'ObjectType': 'Computer'},
        ])

    def test_is_idempotent(self):
        document = broken_document()
        repair_output.repair_document(document)
        already_fixed = json.loads(json.dumps(document))

        self.assertEqual(repair_output.repair_document(document), 0)
        self.assertEqual(document, already_fixed)

    def test_mixed_entries_only_touch_the_strings(self):
        document = {'data': [{'AllowedToDelegate': [
            {'ObjectIdentifier': 'S-1-5-21-1-2-3-2001', 'ObjectType': 'Computer'},
            'SERVER3.CORP.LOCAL',
        ]}]}
        self.assertEqual(repair_output.repair_document(document), 1)
        self.assertEqual(document['data'][0]['AllowedToDelegate'][0]['ObjectType'], 'Computer')
        self.assertEqual(document['data'][0]['AllowedToDelegate'][1],
                         {'ObjectIdentifier': 'SERVER3.CORP.LOCAL', 'ObjectType': 'Computer'})

    def test_leaves_everything_else_alone(self):
        document = broken_document()
        before = json.loads(json.dumps(document))
        repair_output.repair_document(document)

        self.assertEqual(document['meta'], before['meta'])
        for index, entry in enumerate(document['data']):
            for field in ('ObjectIdentifier', 'Properties', 'Aces', 'HasSIDHistory'):
                if field in before['data'][index]:
                    self.assertEqual(entry[field], before['data'][index][field],
                                     '%s must not be touched' % field)

    def test_does_not_guess_at_ambiguous_fields(self):
        # A string here could be any kind of principal, so rewriting it would be
        # a guess. Better left for a re-collection.
        document = {'data': [{'HasSIDHistory': ['S-1-5-21-9-9-9-1105']}]}
        self.assertEqual(repair_output.repair_document(document), 0)
        self.assertEqual(document['data'][0]['HasSIDHistory'], ['S-1-5-21-9-9-9-1105'])

    def test_rejects_documents_that_are_not_bloodhound_output(self):
        self.assertIsNone(repair_output.repair_document({'something': 'else'}))
        self.assertIsNone(repair_output.repair_document([]))


class TestRepairFiles(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def write(self, name, document):
        path = os.path.join(self.tmpdir, name)
        with open(path, 'w') as handle:
            json.dump(document, handle)
        return path

    def test_repairs_a_file_and_keeps_a_backup(self):
        path = self.write('users.json', broken_document())

        self.assertEqual(repair_output.repair_json_file(path), 2)

        with open(path) as handle:
            repaired = json.load(handle)
        self.assertEqual(repaired['data'][0]['AllowedToDelegate'][0],
                         {'ObjectIdentifier': 'S-1-5-21-1-2-3-2001', 'ObjectType': 'Computer'})
        self.assertEqual(repaired['meta']['count'], 2)

        # The original is still there untouched
        with open(path + '.bak') as handle:
            original = json.load(handle)
        self.assertEqual(original['data'][0]['AllowedToDelegate'][0], 'S-1-5-21-1-2-3-2001')

    def test_no_backup_option(self):
        path = self.write('users.json', broken_document())
        repair_output.repair_json_file(path, backup=False)
        self.assertFalse(os.path.exists(path + '.bak'))

    def test_a_file_needing_no_changes_is_left_byte_identical(self):
        document = broken_document()
        repair_output.repair_document(document)
        path = self.write('users.json', document)
        with open(path, 'rb') as handle:
            before = handle.read()

        self.assertEqual(repair_output.repair_json_file(path), 0)

        with open(path, 'rb') as handle:
            self.assertEqual(handle.read(), before)
        self.assertFalse(os.path.exists(path + '.bak'), 'no rewrite means no backup')

    def test_invalid_json_raises_rather_than_destroying_the_file(self):
        path = os.path.join(self.tmpdir, 'truncated.json')
        # What an interrupted collection leaves behind: no closing metadata
        with open(path, 'w') as handle:
            handle.write('{"data":[{"ObjectIdentifier":"S-1-5-21-1-2-3-1105"}')

        with self.assertRaises(ValueError):
            repair_output.repair_json_file(path)

        # The unreadable file must still be exactly as it was
        with open(path) as handle:
            self.assertEqual(handle.read(),
                             '{"data":[{"ObjectIdentifier":"S-1-5-21-1-2-3-1105"}')

    def test_non_bloodhound_json_is_skipped(self):
        path = self.write('other.json', {'something': 'else'})
        self.assertIsNone(repair_output.repair_json_file(path))
        self.assertFalse(os.path.exists(path + '.bak'))

    def test_repairs_a_zip_archive(self):
        path = os.path.join(self.tmpdir, 'bloodhound.zip')
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('20260928_users.json', json.dumps(broken_document()))
            archive.writestr('20260928_computers.json', json.dumps(broken_document()))

        self.assertEqual(repair_output.repair_zip_file(path), 4)

        with zipfile.ZipFile(path) as archive:
            self.assertEqual(sorted(archive.namelist()),
                             ['20260928_computers.json', '20260928_users.json'])
            for name in archive.namelist():
                document = json.loads(archive.read(name).decode('utf-8'))
                self.assertEqual(document['data'][0]['AllowedToDelegate'][0]['ObjectType'],
                                 'Computer')
                self.assertEqual(document['meta']['type'], 'users')
        self.assertTrue(os.path.exists(path + '.bak'))

    def test_zip_keeps_members_that_are_not_json(self):
        path = os.path.join(self.tmpdir, 'bloodhound.zip')
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('users.json', json.dumps(broken_document()))
            archive.writestr('notes.txt', 'keep me')

        repair_output.repair_zip_file(path)

        with zipfile.ZipFile(path) as archive:
            self.assertEqual(archive.read('notes.txt'), b'keep me')

    def test_repair_path_dispatches_on_extension(self):
        json_path = self.write('users.json', broken_document())
        zip_path = os.path.join(self.tmpdir, 'out.ZIP')
        with zipfile.ZipFile(zip_path, 'w') as archive:
            archive.writestr('users.json', json.dumps(broken_document()))

        self.assertEqual(repair_output.repair_path(json_path), 2)
        self.assertEqual(repair_output.repair_path(zip_path), 2)


if __name__ == '__main__':
    unittest.main()


def certtemplates_document(*identifiers):
    return {
        'data': [{'ObjectIdentifier': i,
                  'Properties': {'name': '%s@CORP.LOCAL' % i, 'domainsid': 'S-1-5-21-1-2-3'},
                  'Aces': []} for i in identifiers],
        'meta': {'methods': 0, 'type': 'certtemplates', 'count': len(identifiers), 'version': 5},
    }


def enterprisecas_document(published=(), domainsid='S-1-5-21-1-2-3'):
    return {
        'data': [{'ObjectIdentifier': 'CA-1',
                  'Properties': {'name': 'ISSUING-CA@CORP.LOCAL', 'domainsid': domainsid,
                                 'certthumbprint': 'ABC123'},
                  'EnabledCertTemplates': [{'ObjectIdentifier': i, 'ObjectType': 'CertTemplate'}
                                           for i in published],
                  'Aces': []}],
        'meta': {'methods': 0, 'type': 'enterprisecas', 'count': 1, 'version': 5},
    }


def ntauthstores_document(thumbprints=('ABC123',)):
    return {
        'data': [{'ObjectIdentifier': 'NTAUTH-1', 'DomainSID': 'S-1-5-21-1-2-3',
                  'Properties': {'name': 'NTAUTHCERTIFICATES@CORP.LOCAL'},
                  'CertThumbprints': list(thumbprints), 'Aces': []}],
        'meta': {'methods': 0, 'type': 'ntauthstores', 'count': 1, 'version': 5},
    }


class TestAdcsRepair(unittest.TestCase):
    """
    The AD CS properties BloodHound gates the certificate paths on were never
    collected, but all three are derivable from what is already in the files,
    so an affected collection does not have to be re-run.
    """
    def test_enabled_follows_what_the_cas_publish(self):
        templates = certtemplates_document('T-1', 'T-2')
        context = repair_output.collect_context([enterprisecas_document(published=['T-1'])])

        self.assertEqual(repair_output.repair_document(templates, context), 2)
        self.assertTrue(templates['data'][0]['Properties']['enabled'])
        self.assertFalse(templates['data'][1]['Properties']['enabled'],
                         'a template no CA publishes is not enabled')

    def test_enabled_match_is_case_insensitive_on_the_guid(self):
        templates = certtemplates_document('aaaa-bbbb')
        context = repair_output.collect_context([enterprisecas_document(published=['AAAA-BBBB'])])
        repair_output.repair_document(templates, context)
        self.assertTrue(templates['data'][0]['Properties']['enabled'])

    def test_an_existing_enabled_value_is_left_alone(self):
        templates = certtemplates_document('T-1')
        templates['data'][0]['Properties']['enabled'] = True
        # T-1 is not published, but the collected value wins over our inference
        context = repair_output.collect_context([enterprisecas_document(published=[])])
        self.assertEqual(repair_output.repair_document(templates, context), 0)
        self.assertTrue(templates['data'][0]['Properties']['enabled'])

    def test_templates_are_not_marked_disabled_without_the_ca_file(self):
        # Guessing "disabled" for everything would be worse than leaving it
        # absent, since it reads as a deliberate finding
        templates = certtemplates_document('T-1')
        self.assertEqual(repair_output.repair_document(templates, None), 0)
        self.assertNotIn('enabled', templates['data'][0]['Properties'])

    def test_ntauth_thumbprints_are_copied_into_properties(self):
        store = ntauthstores_document(['ABC123', 'DEF456'])
        self.assertEqual(repair_output.repair_document(store, {}), 1)
        self.assertEqual(store['data'][0]['Properties']['certthumbprints'], ['ABC123', 'DEF456'])
        # The top-level copy is left in place
        self.assertEqual(store['data'][0]['CertThumbprints'], ['ABC123', 'DEF456'])

    def test_ntauth_repair_is_idempotent(self):
        store = ntauthstores_document()
        repair_output.repair_document(store, {})
        self.assertEqual(repair_output.repair_document(store, {}), 0)

    def test_ntauth_without_thumbprints_is_left_alone(self):
        store = ntauthstores_document()
        del store['data'][0]['CertThumbprints']
        self.assertEqual(repair_output.repair_document(store, {}), 0)
        self.assertNotIn('certthumbprints', store['data'][0]['Properties'])

    def test_enterprise_ca_domain_sid_is_backfilled(self):
        cas = enterprisecas_document()
        self.assertEqual(repair_output.repair_document(cas, {}), 1)
        self.assertEqual(cas['data'][0]['DomainSID'], 'S-1-5-21-1-2-3')

    def test_enterprise_ca_without_a_domainsid_property_is_left_alone(self):
        cas = enterprisecas_document()
        del cas['data'][0]['Properties']['domainsid']
        self.assertEqual(repair_output.repair_document(cas, {}), 0)
        self.assertNotIn('DomainSID', cas['data'][0])

    def test_other_collection_types_are_untouched_by_the_adcs_repairs(self):
        users = broken_document()
        before_keys = set(users['data'][0])
        repair_output.repair_document(users, {})
        self.assertEqual(set(users['data'][0]), before_keys)


class TestAdcsRepairAcrossFiles(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def write(self, name, document):
        path = os.path.join(self.tmpdir, name)
        with open(path, 'w') as handle:
            json.dump(document, handle)
        return path

    def test_build_context_reads_the_ca_file_from_the_set(self):
        self.write('certtemplates.json', certtemplates_document('T-1'))
        ca_path = self.write('enterprisecas.json', enterprisecas_document(published=['T-1']))
        template_path = os.path.join(self.tmpdir, 'certtemplates.json')

        context = repair_output.build_context([template_path, ca_path])
        self.assertEqual(context['enabled_templates'], {'T-1'})

        repair_output.repair_json_file(template_path, context=context)
        with open(template_path) as handle:
            self.assertTrue(json.load(handle)['data'][0]['Properties']['enabled'])

    def test_build_context_tolerates_unreadable_files(self):
        good = self.write('enterprisecas.json', enterprisecas_document(published=['T-1']))
        bad = os.path.join(self.tmpdir, 'truncated.json')
        with open(bad, 'w') as handle:
            handle.write('{"data":[')
        # The broken file is reported when it is repaired, not here
        self.assertEqual(repair_output.build_context([bad, good])['enabled_templates'], {'T-1'})

    def test_zip_resolves_context_from_its_own_members(self):
        path = os.path.join(self.tmpdir, 'bloodhound.zip')
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('certtemplates.json', json.dumps(certtemplates_document('T-1', 'T-2')))
            archive.writestr('enterprisecas.json',
                             json.dumps(enterprisecas_document(published=['T-1'])))
            archive.writestr('ntauthstores.json', json.dumps(ntauthstores_document()))

        self.assertTrue(repair_output.repair_zip_file(path) > 0)

        with zipfile.ZipFile(path) as archive:
            templates = json.loads(archive.read('certtemplates.json').decode('utf-8'))
            self.assertTrue(templates['data'][0]['Properties']['enabled'])
            self.assertFalse(templates['data'][1]['Properties']['enabled'])
            store = json.loads(archive.read('ntauthstores.json').decode('utf-8'))
            self.assertIn('certthumbprints', store['data'][0]['Properties'])
            cas = json.loads(archive.read('enterprisecas.json').decode('utf-8'))
            self.assertEqual(cas['data'][0]['DomainSID'], 'S-1-5-21-1-2-3')
