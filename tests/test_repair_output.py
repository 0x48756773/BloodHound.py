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
