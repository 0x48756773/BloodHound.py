#!/usr/bin/env python
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
Repair BloodHound output collected before AllowedToDelegate was emitted as
typed principals.

Older output put bare strings in that field, which BloodHound refuses with

    json: cannot unmarshal string into Go struct field
    User.AllowedToDelegate of type ein.TypedPrincipal

and since an unmarshal error rejects the whole file, one account with
constrained delegation configured was enough to lose every user or computer in
it. This rewrites those strings into the objects BloodHound expects, so a
collection that already took an hour does not have to be run again.

    python repair_output.py 20260928153000_users.json
    python repair_output.py 20260928153000_*.json
    python repair_output.py 20260928153000_bloodhound.zip

Safe to run more than once: entries that are already correct are left alone.
The original is kept as <name>.bak unless --no-backup is given.
"""
from __future__ import print_function

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
import zipfile

# Fields BloodHound reads as a list of typed principals, mapped to the object
# type a bare string in them stands for. Only fields whose type is unambiguous
# belong here: a delegation target is always a computer, whereas a string in
# HasSIDHistory could be any kind of principal and is better left alone than
# guessed at.
STRING_PRINCIPAL_FIELDS = {
    'AllowedToDelegate': 'Computer',
}


def repair_object(obj):
    """
    Fix one user or computer entry. Returns how many values were rewritten.
    """
    if not isinstance(obj, dict):
        return 0
    fixed = 0
    for field, objecttype in STRING_PRINCIPAL_FIELDS.items():
        values = obj.get(field)
        if not isinstance(values, list):
            continue
        for index, value in enumerate(values):
            # Anything already an object is either correct or something this
            # script has no business rewriting
            if isinstance(value, str):
                values[index] = {'ObjectIdentifier': value, 'ObjectType': objecttype}
                fixed += 1
    return fixed


def document_type(document):
    """
    The collection type a document holds, from its meta block.
    """
    try:
        return document['meta']['type']
    except (KeyError, TypeError):
        return None


def collect_context(documents):
    """
    Gather the facts that repairing one file needs from the others.

    The only cross-file dependency is the enabled flag on a certificate
    template: whether a template is enabled is a property of the CAs that
    publish it, which lives in enterprisecas.json.
    """
    enabled_templates = set()
    for document in documents:
        if document_type(document) != 'enterprisecas':
            continue
        for ca in document.get('data') or []:
            if not isinstance(ca, dict):
                continue
            for template in ca.get('EnabledCertTemplates') or []:
                identifier = (template or {}).get('ObjectIdentifier')
                if identifier:
                    enabled_templates.add(identifier.upper())
    return {'enabled_templates': enabled_templates}


def repair_cert_template(obj, context):
    """
    Add the enabled flag, which older collections never wrote at all.

    A template is enabled when an enterprise CA publishes it, which is exactly
    what the EnabledCertTemplates list of each CA records.
    """
    if 'enabled' in obj.get('Properties', {}):
        return 0
    identifier = (obj.get('ObjectIdentifier') or '').upper()
    obj.setdefault('Properties', {})['enabled'] = identifier in context.get('enabled_templates', set())
    return 1


def repair_ntauth_store(obj, context):
    """
    Copy the certificate thumbprints into Properties.

    BloodHound matches an enterprise CA's certthumbprint against this list to
    establish the NT authentication trust that every certificate path runs
    through, and reads it as a node property rather than from the top level.
    """
    properties = obj.setdefault('Properties', {})
    if 'certthumbprints' in properties:
        return 0
    thumbprints = obj.get('CertThumbprints')
    if not isinstance(thumbprints, list):
        return 0
    properties['certthumbprints'] = thumbprints
    return 1


def repair_enterprise_ca(obj, context):
    """
    Add the DomainSID that ties a CA to the domain it issues for. The value is
    already on the object as the domainsid property.
    """
    if obj.get('DomainSID'):
        return 0
    domainsid = obj.get('Properties', {}).get('domainsid')
    if not domainsid:
        return 0
    obj['DomainSID'] = domainsid
    return 1


# Repairs that apply only to one collection type, keyed on the meta type
TYPED_REPAIRS = {
    'certtemplates': repair_cert_template,
    'ntauthstores': repair_ntauth_store,
    'enterprisecas': repair_enterprise_ca,
}


def repair_document(document, context=None):
    """
    Fix a parsed BloodHound JSON document in place. Returns how many values
    were rewritten, or None if this does not look like BloodHound output.
    """
    if not isinstance(document, dict) or not isinstance(document.get('data'), list):
        return None
    fixed = sum(repair_object(entry) for entry in document['data'])

    typed_repair = TYPED_REPAIRS.get(document_type(document))
    if typed_repair is not None:
        # Templates need to know what the CAs publish; without that context we
        # would mark every template disabled, which is worse than leaving the
        # property absent.
        if typed_repair is repair_cert_template and context is None:
            logging.warning('Cannot work out which certificate templates are enabled without '
                            'the enterprisecas file, so the enabled flag is being left unset')
        else:
            fixed += sum(typed_repair(entry, context or {})
                         for entry in document['data'] if isinstance(entry, dict))
    return fixed


def repair_json_bytes(raw, context=None):
    """
    Fix a JSON document held in memory. Returns (output bytes, values fixed),
    with the output left untouched when there was nothing to do.
    """
    document = json.loads(raw.decode('utf-8'))
    fixed = repair_document(document, context)
    if not fixed:
        return raw, fixed
    return json.dumps(document).encode('utf-8'), fixed


def repair_json_file(path, backup=True, context=None):
    """
    Fix one .json file on disk. Returns the number of values rewritten, or None
    when the file was not BloodHound output.
    """
    with open(path, 'rb') as handle:
        raw = handle.read()

    output, fixed = repair_json_bytes(raw, context)
    if fixed is None:
        logging.warning('%s does not look like BloodHound output, skipping', path)
        return None
    if not fixed:
        logging.info('%s needs no changes', path)
        return 0

    if backup:
        shutil.copy2(path, path + '.bak')
    # Write to a temporary file in the same directory and move it into place, so
    # an interrupted write cannot leave a half-written file where the original
    # used to be.
    directory = os.path.dirname(os.path.abspath(path))
    handle, temporary = tempfile.mkstemp(dir=directory, suffix='.tmp')
    try:
        with os.fdopen(handle, 'wb') as out:
            out.write(output)
        shutil.move(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    logging.info('%s: fixed %d value(s)', path, fixed)
    return fixed


def repair_zip_file(path, backup=True):
    """
    Fix the .json members of a zip archive, as produced by --zip.
    """
    fixed_total = 0
    members = []

    # First pass over the archive to learn what the CAs publish, which the
    # certificate templates in the same archive need
    documents = []
    with zipfile.ZipFile(path, 'r') as archive:
        for info in archive.infolist():
            if not info.filename.lower().endswith('.json'):
                continue
            try:
                documents.append(json.loads(archive.read(info.filename).decode('utf-8')))
            except ValueError:
                continue
    context = collect_context(documents)

    with zipfile.ZipFile(path, 'r') as archive:
        for info in archive.infolist():
            raw = archive.read(info.filename)
            if info.filename.lower().endswith('.json'):
                try:
                    raw, fixed = repair_json_bytes(raw, context)
                except ValueError as exc:
                    logging.error('%s in %s is not valid JSON: %s', info.filename, path, exc)
                    fixed = 0
                if fixed:
                    fixed_total += fixed
                    logging.info('%s: fixed %d value(s) in %s',
                                 path, fixed, info.filename)
            members.append((info, raw))

    if not fixed_total:
        logging.info('%s needs no changes', path)
        return 0

    if backup:
        shutil.copy2(path, path + '.bak')
    directory = os.path.dirname(os.path.abspath(path))
    handle, temporary = tempfile.mkstemp(dir=directory, suffix='.tmp')
    os.close(handle)
    try:
        with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
            for info, raw in members:
                archive.writestr(info.filename, raw)
        shutil.move(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    return fixed_total


def repair_path(path, backup=True, context=None):
    if path.lower().endswith('.zip'):
        return repair_zip_file(path, backup=backup)
    return repair_json_file(path, backup=backup, context=context)


def build_context(paths):
    """
    Read the loose .json inputs once to learn what repairing them needs from
    each other. Unreadable files are skipped here; they are reported properly
    when they are repaired.
    """
    documents = []
    for path in paths:
        if path.lower().endswith('.zip') or not os.path.isfile(path):
            continue
        try:
            with open(path, 'rb') as handle:
                documents.append(json.loads(handle.read().decode('utf-8')))
        except (ValueError, IOError, OSError, UnicodeDecodeError):
            continue
    return collect_context(documents)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('files', metavar='FILE', nargs='+',
                        help='BloodHound .json files, or a .zip produced with --zip')
    parser.add_argument('--no-backup', action='store_true',
                        help='Do not keep the original as <name>.bak')
    parser.add_argument('-v', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG if args.v else logging.INFO,
                        format='%(levelname)s: %(message)s')

    # Pass over the inputs first: the enabled flag on a certificate template
    # depends on the enterprise CA file, so pass every file from one collection
    # in together
    context = build_context(args.files)
    if not context['enabled_templates']:
        logging.debug('No published certificate templates found in the given files')

    total = 0
    failed = False
    for path in args.files:
        if not os.path.isfile(path):
            logging.error('%s does not exist', path)
            failed = True
            continue
        try:
            fixed = repair_path(path, backup=not args.no_backup, context=context)
        except ValueError as exc:
            # A collection that was interrupted can leave a file without its
            # closing metadata, which is a different problem to this one
            logging.error('%s is not valid JSON, so it cannot be repaired: %s', path, exc)
            logging.error('A file left incomplete by an interrupted collection '
                          'cannot be recovered this way')
            failed = True
            continue
        except (IOError, OSError) as exc:
            logging.error('Could not repair %s: %s', path, exc)
            failed = True
            continue
        if fixed:
            total += fixed

    if total:
        logging.info('Fixed %d value(s) in total, the files can now be imported', total)
    else:
        logging.info('Nothing needed fixing')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
