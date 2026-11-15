# SPDX-License-Identifier: Apache-2.0
"""Private Linux native tools shared by the existing AOT probe and Go cgo checks.

This module is independently authored Contracts tooling. It never changes system
PATH, alternatives, packages or existing installations. Provisioning is explicit;
normal build/check entry points only select and verify already installed tools.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import difflib
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'eng/native-toolchain.json'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_lock(path=None):
    path = LOCK if path is None else path
    value = json.loads(path.read_text(encoding='utf-8'))
    require(value.get('schemaVersion') == 1 and value.get('platform') == 'linux-amd64', 'Invalid native tool selector')
    require(value.get('status') == 'ready' and value.get('pendingReason') is None,
            'Native tool qualification is pending: ' + str(value.get('pendingReason', 'missing review')))
    for name in ('llvm', 'binutils'):
        row = value[name]
        require(re.fullmatch(r'[0-9]+\.[0-9]+(?:\.[0-9]+)?', row['version']), 'Native tool version must be stable and exact')
        archive = row['archive']
        require(re.fullmatch('[0-9a-f]{64}', archive['sha256']) and isinstance(archive['size'], int)
                and archive['size'] > 0 and archive['root'] == PurePosixPath(archive['root']).name,
                'Invalid native source artifact identity')
    require(value['llvm']['archive']['url'].startswith('https://github.com/llvm/llvm-project/releases/download/llvmorg-'),
            'LLVM source must be the official release artifact')
    require(value['binutils']['archive']['url'].startswith('https://ftp.gnu.org/gnu/binutils/'),
            'Binutils source must be the official release artifact')
    patch = value['binutils'].get('patch')
    require(isinstance(patch, dict) and patch.get('mode') == 'external-build-tool-byte-edits-v1'
            and {row['path'] for row in patch['files']} == {'ld/ldlang.c', 'ld/mri.c'}, 'Invalid external tool source recipe')
    require(all(edit['insert'] in {'', ' ATTRIBUTE_UNUSED'} for row in patch['files'] for edit in row['edits']),
            'External tool recipe contains an unreviewed insertion')
    return value


def exact_version(output, expected):
    return re.search(r'(?<![0-9A-Za-z.+-])' + re.escape(expected) + r'(?![0-9A-Za-z.+-])', output) is not None


def tool_roots(value, destination=None):
    root = Path(destination or os.environ.get('ARCFORGES_TOOLCHAIN_ROOT') or
                Path.home() / '.local/share/arcforges/toolchains').resolve()
    return root, root / ('llvm-' + value['llvm']['version']), root / ('binutils-' + value['binutils']['version'])


def linux_only():
    require(platform.system() == 'Linux' and platform.machine().lower() in {'amd64', 'x86_64'},
            'This native tool selection applies only to Linux amd64')


def selected_environment(base=None, destination=None, *, value=None):
    linux_only()
    value = value or load_lock()
    root, llvm, binutils = tool_roots(value, destination)
    env = dict(os.environ if base is None else base)
    env['ARCFORGES_TOOLCHAIN_ROOT'] = str(root)
    env['PATH'] = os.pathsep.join([str(llvm / 'bin'), str(binutils / 'bin'), env.get('PATH', '')])
    env['CC'], env['CXX'] = 'clang', 'clang++'
    return env


def probe(arguments, env):
    result = subprocess.run([str(arg) for arg in arguments], env=env, capture_output=True,
                            text=True, encoding='utf-8', timeout=30, check=False)
    require(result.returncode == 0, 'Native tool probe failed: ' + str(arguments[0]) + ': ' + result.stderr.strip())
    return result.stdout.strip()


def verify_clang_aliases(llvm, major):
    compiler = llvm / 'bin' / ('clang-' + major)
    require(compiler.is_file() and not compiler.is_symlink(), 'The official Clang compiler must remain a regular file')
    for name in ('clang', 'clang++'):
        alias = llvm / 'bin' / name
        require(alias.is_file() and alias.resolve() == compiler.resolve(),
                'LLVM compiler alias does not select the verified official binary: ' + name)


def verify_default_linker_alias(binutils):
    default, bfd = binutils / 'bin/ld', binutils / 'bin/ld.bfd'
    require(default.is_file() and bfd.is_file() and digest(default) == digest(bfd),
            'The default GNU ld must select the exact verified BFD executable')


def check(*, base=None, destination=None):
    value = load_lock()
    env = selected_environment(base, destination, value=value)
    _, llvm, binutils = tool_roots(value, destination)
    paths = {'clang': llvm / 'bin/clang', 'clang++': llvm / 'bin/clang++',
             'llvm-objcopy': llvm / 'bin/llvm-objcopy', 'ld.bfd': binutils / 'bin/ld.bfd', 'ld': binutils / 'bin/ld',
             'ar': binutils / 'bin/ar', 'as': binutils / 'bin/as'}
    evidence = {'platform': 'linux-amd64', 'selectorSha256': digest(LOCK), 'tools': {},
                'environment': {'CC': env['CC'], 'CXX': env['CXX']},
                'aot': {'CppCompilerAndLinker': 'clang', 'LinkerFlavor': 'bfd',
                        'CppLibCreator': 'ar', 'ObjCopyName': 'llvm-objcopy'}}
    llvm_receipt_path = llvm / 'provision-receipt.json'
    require(llvm_receipt_path.is_file(), 'LLVM archive extraction receipt is missing')
    llvm_receipt = json.loads(llvm_receipt_path.read_text(encoding='utf-8'))
    require(llvm_receipt.get('sourceCommit') == value['llvm']['sourceCommit']
            and llvm_receipt.get('sourceArchive', {}).get('actualSha256') == value['llvm']['archive']['sha256'],
            'LLVM extraction receipt differs from the official archive')
    for row in llvm_receipt['archiveFiles']:
        path = llvm / row['path']
        require(path.resolve().is_relative_to(llvm.resolve()) and digest(path) == row['sha256'],
                'LLVM installed archive resource changed: ' + row['path'])
    for name, expected in value['llvm']['binaries'].items():
        require((llvm / name).is_file() and digest(llvm / name) == expected,
                'LLVM installed binary differs from the official archive: ' + name)
    verify_clang_aliases(llvm, value['llvm']['version'].split('.')[0])
    for row in value['llvm']['licences']:
        require((llvm / row['path']).is_file() and digest(llvm / row['path']) == row['sha256'],
                'LLVM full project licence is missing or changed')
    receipt_path = binutils / 'provision-receipt.json'
    require(receipt_path.is_file(), 'The native binutils source/build receipt is missing')
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    require(receipt.get('success') is True and receipt.get('state') == 'installed'
            and receipt.get('sourceArchive', {}).get('sha256') == value['binutils']['archive']['sha256']
            and (receipt.get('localSourceCompatibilityPatch', {}).get('patchSha256') == value['binutils']['patch']['reviewedCompatibilityPatchSha256']
                 or receipt.get('localSourceCompatibilityPatch', {}).get('recipeSha256') == recipe_digest(value['binutils']['patch'])),
            'The installed binutils source/patch identity differs from its selector')
    expected_delta = {row['path']: (row['beforeSha256'], row['afterSha256']) for row in value['binutils']['patch']['files']}
    actual_delta = {row['member'].removeprefix(value['binutils']['archive']['root'] + '/'): (row['originalSha256'], row['actualSha256'])
                    for row in receipt['sourceDeltaVerification']['onlyChanges']}
    require(actual_delta == expected_delta, 'Binutils source changes differ from the exact external tool recipe')
    for row in value['binutils']['licences']:
        require(digest(binutils / 'share/licenses/binutils' / row['path']) == row['sha256'], 'GNU tool licence is missing or changed')
    release = receipt.get('upstreamReleaseIdentity', {})
    require(release.get('declaredRelease') == value['binutils']['version']
            and release.get('actualBannerVersion') == value['binutils']['observedVersion']
            and release.get('tagCommit') == value['binutils']['sourceCommit']
            and release.get('archiveSha256') == value['binutils']['archive']['sha256']
            and release.get('noVersionOrMarkerNormalization') is True,
            'Binutils does not bind the exact signed formal release and its unmodified banner')
    installed = {row['path']: row['sha256'] for row in receipt['installedFiles']}
    for name in ('ld.bfd', 'ld', 'ar', 'as'):
        require(installed.get('bin/' + name) == digest(binutils / 'bin' / name), 'Installed binutils tool changed: ' + name)
    verify_default_linker_alias(binutils)
    for name, path in paths.items():
        selected = shutil.which(name, path=env['PATH'])
        require(selected is not None and Path(selected).resolve() == path.resolve() and path.is_file(),
                'The pinned native tool is absent or shadowed: ' + name)
        output = probe([path, '--version'], env)
        expected = value['llvm']['version'] if name in {'clang', 'clang++', 'llvm-objcopy'} else value['binutils']['observedVersion']
        # Preserve the exact banner of the signed formal release; never truncate a date suffix.
        require(exact_version(output, expected),
                'Native tool does not identify the exact reviewed release: ' + name)
        evidence['tools'][name] = {'path': str(path), 'resolvedPath': str(path.resolve()),
                                   'sha256': digest(path), 'version': output.splitlines()[0]}
    resource = Path(probe([llvm / 'bin/clang', '-print-resource-dir'], env)).resolve()
    require(resource == (llvm / 'lib/clang' / value['llvm']['version'].split('.')[0]).resolve() and resource.is_dir(),
            'Clang is selecting a different resource directory')
    linker = Path(probe([llvm / 'bin/clang', '-print-prog-name=ld.bfd'], env)).resolve()
    require(linker == paths['ld.bfd'].resolve(), 'Clang is selecting a different BFD linker: ' + str(linker))
    default_linker = Path(probe([llvm / 'bin/clang', '-print-prog-name=ld'], env)).resolve()
    require(default_linker == paths['ld'].resolve(), 'Go cgo Clang is selecting a different default linker: ' + str(default_linker))
    evidence['binutilsProvisionReceiptSha256'] = digest(receipt_path)
    evidence['clangResourceDirectory'] = str(resource)
    evidence['selectedBfd'] = str(linker)
    evidence['selectedDefaultLd'] = str(default_linker)
    return evidence


@lru_cache(maxsize=4)
def _verify_environment(destination, selector_digest):
    # One native tool identity handoff per process, even when Go spawns several
    # read-only queries. A changed selector/root is a distinct handoff.
    return check(destination=destination)


def aot_environment(base=None):
    value = load_lock()
    root, _, _ = tool_roots(value)
    _verify_environment(str(root), digest(LOCK))
    return selected_environment(base, root, value=value)


def aot_arguments():
    return ['-p:CppCompilerAndLinker=clang', '-p:CppLibCreator=ar', '-p:LinkerFlavor=bfd', '-p:ObjCopyName=llvm-objcopy']


def download(row, directory):
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / (row['sha256'] + '-' + row['url'].rsplit('/', 1)[1])
    if target.exists():
        require(digest(target) == row['sha256'] and (not row.get('size') or target.stat().st_size == row['size']),
                'Cached native artifact has the wrong identity')
        return target
    with tempfile.NamedTemporaryFile(dir=directory, prefix='download-', delete=False) as output:
        temporary = Path(output.name)
        with urllib.request.urlopen(row['url'], timeout=120) as source:
            shutil.copyfileobj(source, output)
    require(digest(temporary) == row['sha256'] and (not row.get('size') or temporary.stat().st_size == row['size']),
            'Official native artifact has the wrong identity: ' + row['url'])
    temporary.replace(target)
    return target


def extract(archive, destination, root_name, *, llvm=False):
    require(not destination.exists(), 'Refusing to overwrite an existing native tool tree')
    destination.mkdir(parents=True)
    with tarfile.open(archive, 'r:xz') as bundle:
        for member in bundle:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and name.parts[0] == root_name,
                    'Unsafe native archive member')
            relative = PurePosixPath(*name.parts[1:])
            if relative == PurePosixPath('.'):
                continue
            if llvm and not (relative.as_posix() in {'bin/clang', 'bin/clang++', 'bin/clang-23', 'bin/llvm-objcopy',
                                                     'include/llvm/Support/LICENSE.TXT'}
                             or relative.as_posix().startswith('lib/clang/23/')):
                continue
            require(member.isfile() or member.isdir() or member.issym(), 'Unexpected native archive member kind')
            member.name = relative.as_posix()
            bundle.extract(member, destination, filter='data')


def recipe_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def edited_bytes(data, row):
    require(hashlib.sha256(data).hexdigest() == row['beforeSha256'], 'External tool input does not match the signed source')
    previous = len(data) + 1
    for edit in row['edits']:
        offset, length = edit['offset'], edit['length']
        require(isinstance(offset, int) and isinstance(length, int) and 0 <= offset <= offset + length <= len(data)
                and offset + length < previous and edit['insert'] in {'', ' ATTRIBUTE_UNUSED'}, 'Invalid source byte edit')
        data = data[:offset] + edit['insert'].encode() + data[offset + length:]
        previous = offset
    require(hashlib.sha256(data).hexdigest() == row['afterSha256'], 'External tool result differs from the reviewed source')
    return data


def prepare_external_source(source, recipe, patch_path):
    changes, contexts = [], []
    for row in recipe['files']:
        relative = PurePosixPath(row['path'])
        require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe external source path')
        path = source / relative
        before = path.read_bytes()
        after = edited_bytes(before, row)
        changes.append((path, after))
        contexts.extend(difflib.unified_diff(before.decode().splitlines(keepends=True), after.decode().splitlines(keepends=True),
                                            fromfile='a/' + row['path'], tofile='b/' + row['path']))
    # This generated diff contains upstream GNU context. It stays with the GNU
    # source/tool cache under its own licence and is never copied into this repo.
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_text('# SPDX-License-Identifier: GPL-3.0-or-later\n' + ''.join(contexts), encoding='utf-8', newline='\n')
    for path, after in changes:
        path.write_bytes(after)


def installed_files(root):
    return [{'path': path.relative_to(root).as_posix(), 'sha256': digest(path), 'size': path.stat().st_size}
            for path in sorted(root.rglob('*')) if path.is_file() and not path.is_symlink()]


def verify_built_source(source, archive, archive_root, recipe):
    changed = {row['path']: row for row in recipe['files']}
    members, deltas = set(), []
    with tarfile.open(archive, 'r:xz') as bundle:
        for member in bundle:
            require(member.isfile() and member.name.startswith(archive_root + '/'), 'Unexpected binutils source member')
            relative = member.name.removeprefix(archive_root + '/')
            original = hashlib.sha256(bundle.extractfile(member).read()).hexdigest()
            expected = changed[relative]['afterSha256'] if relative in changed else original
            require(digest(source / relative) == expected, 'Native build changed an unreviewed source: ' + relative)
            members.add(relative)
            if relative in changed:
                deltas.append({'member': member.name, 'originalSha256': original, 'actualSha256': expected})
    require({path.relative_to(source).as_posix() for path in source.rglob('*') if path.is_file()} == members,
            'Native build added or omitted source files')
    return {'archiveMembersCompared': len(members), 'onlyChanges': deltas, 'onlyReviewedPatchDiffers': True}


def install(destination):
    linux_only()
    value = load_lock()
    root, llvm, binutils = tool_roots(value, destination)
    root.mkdir(parents=True, exist_ok=True)
    archives = root / 'downloads'
    if not llvm.exists():
        archive = download(value['llvm']['archive'], archives)
        extract(archive, llvm, value['llvm']['archive']['root'], llvm=True)
        extracted = installed_files(llvm)
        for row in value['llvm']['licences']:
            legal = download(row, archives)
            target = llvm / row['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(legal, target)
        (llvm / 'provision-receipt.json').write_text(json.dumps({'sourceCommit': value['llvm']['sourceCommit'],
            'sourceArchive': {'actualSha256': value['llvm']['archive']['sha256']}, 'archiveFiles': extracted}, indent=2) + '\n', encoding='utf-8')
    if not binutils.exists():
        source = root / 'sources' / value['binutils']['archive']['root']
        build = root / 'build' / value['binutils']['archive']['root']
        require(not source.exists() and not build.exists(), 'Prior native source/build attempt exists; inspect it before retrying')
        archive = download(value['binutils']['archive'], archives)
        extract(archive, source, value['binutils']['archive']['root'])
        patch_path = root / 'patches/binutils-clang23.patch'
        prepare_external_source(source, value['binutils']['patch'], patch_path)
        build.mkdir(parents=True)
        env = dict(os.environ)
        env['PATH'] = str(llvm / 'bin') + os.pathsep + env.get('PATH', '')
        env['CC'], env['CXX'] = str(llvm / 'bin/clang'), str(llvm / 'bin/clang++')
        for name, expected in value['llvm']['binaries'].items():
            require(digest(llvm / name) == expected, 'Bootstrap LLVM binary differs from the official artifact')
        commands = [[str(source / 'configure'), '--prefix=' + str(binutils), *value['binutils']['configureArguments']],
                    ['make', '-j2', *value['binutils']['makeTargets']], ['make', *value['binutils']['installTargets']]]
        for arguments in commands:
            subprocess.run(arguments, cwd=build, env=env, check=True)
        delta = verify_built_source(source, archive, value['binutils']['archive']['root'], value['binutils']['patch'])
        for row in value['binutils']['licences']:
            require(digest(source / row['path']) == row['sha256'], 'GNU source licence differs')
            target = binutils / 'share/licenses/binutils' / row['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / row['path'], target)
        receipt = {'success': True, 'state': 'installed', 'sourceArchive': value['binutils']['archive'],
            'localSourceCompatibilityPatch': {'patchSha256': digest(patch_path), 'recipeSha256': recipe_digest(value['binutils']['patch'])},
            'sourceDeltaVerification': delta,
            'upstreamReleaseIdentity': {'declaredRelease': value['binutils']['version'], 'actualBannerVersion': value['binutils']['observedVersion'],
                'tagCommit': value['binutils']['sourceCommit'], 'archiveSha256': value['binutils']['archive']['sha256'], 'noVersionOrMarkerNormalization': True},
            'installedFiles': installed_files(binutils), 'commands': commands, 'buildEnvironment': {'CC': env['CC'], 'CXX': env['CXX']},
            'sourceRoot': str(source), 'contextPatch': str(patch_path), 'provisionedAtUtc': datetime.now(timezone.utc).isoformat()}
        (binutils / 'provision-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return check(destination=root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('check', 'install'):
        sub.add_parser(name).add_argument('--destination', type=Path)
    sub.add_parser('run').add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command == 'run':
        arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
        require(bool(arguments), 'A child command is required')
        raise SystemExit(subprocess.run(arguments, env=aot_environment()).returncode)
    result = install(args.destination) if args.command == 'install' else check(destination=args.destination)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
