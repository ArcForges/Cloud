# SPDX-License-Identifier: Apache-2.0
"""Offline selector/archive refusal tests; no native build or upstream download."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'eng'))
import native_toolchain as native
import center


class NativeToolchainGuards(unittest.TestCase):
    def test_default_go_linker_is_the_same_verified_bfd_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'bin').mkdir()
            (root / 'bin/ld.bfd').write_bytes(b'verified BFD executable fixture')
            (root / 'bin/ld').write_bytes(b'older default ld')
            with self.assertRaisesRegex(ValueError, 'default GNU ld'):
                native.verify_default_linker_alias(root)
            (root / 'bin/ld').write_bytes((root / 'bin/ld.bfd').read_bytes())
            native.verify_default_linker_alias(root)

    def test_clang_aliases_are_bound_before_any_tool_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'bin').mkdir()
            (root / 'bin/clang-23').write_bytes(b'verified official binary fixture')
            with self.assertRaisesRegex(ValueError, 'compiler alias'):
                native.verify_clang_aliases(root, '23')
            # A substitute can print the right version and still be a different
            # executable. Alias identity must fail before it is ever invoked.
            (root / 'bin/clang').write_bytes(b'substitute version-printing program')
            (root / 'bin/clang++').write_bytes(b'substitute version-printing program')
            with self.assertRaisesRegex(ValueError, 'compiler alias'):
                native.verify_clang_aliases(root, '23')
            if os.name != 'nt':
                (root / 'bin/clang').unlink()
                (root / 'bin/clang++').unlink()
                (root / 'bin/clang').symlink_to('clang-23')
                (root / 'bin/clang++').symlink_to('clang')
                native.verify_clang_aliases(root, '23')
                (root / 'bin/clang++').unlink()
                (root / 'bin/other-clang').write_bytes(b'different compiler')
                (root / 'bin/clang++').symlink_to('other-clang')
                with self.assertRaisesRegex(ValueError, 'compiler alias'):
                    native.verify_clang_aliases(root, '23')

    def test_external_source_edits_bind_complete_original_and_result_bytes(self):
        before, after = b'alpha\nunused\nomega\n', b'alpha\nomega\n'
        row = {'path': 'input.c', 'beforeSha256': hashlib.sha256(before).hexdigest(),
               'afterSha256': hashlib.sha256(after).hexdigest(),
               'edits': [{'offset': 6, 'length': 7, 'insert': ''}]}
        self.assertEqual(after, native.edited_bytes(before, row))
        with self.assertRaisesRegex(ValueError, 'signed source'):
            native.edited_bytes(before + b'changed', row)
        wrong = copy.deepcopy(row)
        wrong['edits'][0]['length'] = 6
        with self.assertRaisesRegex(ValueError, 'reviewed source'):
            native.edited_bytes(before, wrong)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'source').mkdir()
            (root / 'source/input.c').write_bytes(before)
            patch_path = root / 'external-tool-cache/context.patch'
            native.prepare_external_source(root / 'source', {'files': [row]}, patch_path)
            self.assertEqual(after, (root / 'source/input.c').read_bytes())
            self.assertTrue(patch_path.read_text().startswith('# SPDX-License-Identifier: GPL-3.0-or-later\n'))
            archive = self.archive(root, [('SOURCE/input.c', before)])
            evidence = native.verify_built_source(root / 'source', archive, 'SOURCE', {'files': [row]})
            self.assertEqual(1, evidence['archiveMembersCompared'])
            (root / 'source/extra.c').write_bytes(b'undeclared build change')
            with self.assertRaisesRegex(ValueError, 'added or omitted source'):
                native.verify_built_source(root / 'source', archive, 'SOURCE', {'files': [row]})

    def test_pending_selector_cannot_execute_or_install_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            selector = Path(temporary) / 'native-toolchain.json'
            selector.write_text(json.dumps({'schemaVersion': 1, 'platform': 'linux-amd64', 'status': 'pending',
                                            'pendingReason': 'Unreviewed source patch'}), encoding='utf-8')
            with patch.object(native, 'LOCK', selector), patch.object(native, 'probe', side_effect=AssertionError('unexpected process')):
                with self.assertRaisesRegex(ValueError, 'qualification is pending'):
                    native.check()
                with patch.object(native.platform, 'system', return_value='Linux'), self.assertRaisesRegex(ValueError, 'qualification is pending'):
                    native.install(Path(temporary) / 'tools')

    def test_exact_official_banner_is_not_truncated_or_prefix_matched(self):
        self.assertTrue(native.exact_version('GNU ld (GNU Binutils) 2.47.20260726', '2.47.20260726'))
        for actual in ('2.47.20260726-preview', '2.47.20260726.1', '2.47.20260726+local', '12.47.20260726'):
            with self.subTest(actual=actual):
                self.assertFalse(native.exact_version(actual, '2.47.20260726'))
        self.assertFalse(native.exact_version('GNU ld (GNU Binutils) 2.47.20260726', '2.47'))

    def test_child_selection_preserves_parent_and_names_both_compilers(self):
        selector = {'llvm': {'version': '23.1.5'}, 'binutils': {'version': '2.47'}}
        parent = {'PATH': 'existing-tools', 'CC': 'old-compiler', 'KEEP': 'value'}
        before = copy.deepcopy(parent)
        with patch.object(native.platform, 'system', return_value='Linux'), patch.object(native.platform, 'machine', return_value='x86_64'):
            result = native.selected_environment(parent, ROOT / 'artifacts/offline-native-fixture', value=selector)
        self.assertEqual(before, parent)
        self.assertEqual(('clang', 'clang++'), (result['CC'], result['CXX']))
        self.assertEqual('value', result['KEEP'])
        self.assertEqual('existing-tools', result['PATH'].split(os.pathsep)[-1])

    def test_windows_cgo_disabled_path_requires_no_linux_tool(self):
        with patch.object(center, 'WINDOWS', True), \
                patch.object(native, 'aot_environment', side_effect=AssertionError('Linux tool selection was invoked')):
            value = center.go_environment()
        self.assertEqual('local', value['GOTOOLCHAIN'])
        self.assertEqual('0', value['CGO_ENABLED'])

    def archive(self, root, members):
        path = root / 'fixture.tar.xz'
        with tarfile.open(path, 'w:xz') as bundle:
            for name, data in members:
                item = tarfile.TarInfo(name)
                item.size = len(data)
                bundle.addfile(item, io.BytesIO(data))
        return path

    def test_archive_traversal_is_rejected_and_existing_install_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = self.archive(root, [('LLVM/../outside', b'invalid')])
            with self.assertRaisesRegex(ValueError, 'Unsafe native archive member'):
                native.extract(archive, root / 'new-install', 'LLVM')
            existing = root / 'existing'
            existing.mkdir()
            (existing / 'keep').write_bytes(b'old installation')
            with self.assertRaisesRegex(ValueError, 'overwrite an existing'):
                native.extract(archive, existing, 'LLVM')
            self.assertEqual(b'old installation', (existing / 'keep').read_bytes())

    def test_llvm_extraction_keeps_compiler_resources_and_omits_unneeded_development_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = self.archive(root, [('LLVM/bin/clang-23', b'compiler'),
                                          ('LLVM/lib/clang/23/include/stddef.h', b'resource'),
                                          ('LLVM/lib/libLLVM.a', b'unused static development archive')])
            target = root / 'install'
            native.extract(archive, target, 'LLVM', llvm=True)
            self.assertEqual(b'compiler', (target / 'bin/clang-23').read_bytes())
            self.assertEqual(b'resource', (target / 'lib/clang/23/include/stddef.h').read_bytes())
            self.assertFalse((target / 'lib/libLLVM.a').exists())


if __name__ == '__main__':
    unittest.main()
