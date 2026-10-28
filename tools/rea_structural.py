#!/usr/bin/env python3
"""Análise estrutural offline de PE e ZIP. Não executa ou extrai binários.
Python 3.8+, apenas biblioteca padrão; saída sem componentes proprietários.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys
import zipfile

MAX_PE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_ENTRIES = 512
MAX_RESOURCES = 1000
MAX_DLLS = 256
MAX_FUNCTIONS = 4096
DRIVERS = ('DeepFrz.sys', 'DeepFrzx64.sys', 'FarSpace.sys', 'FarSpaceX64.sys')
API_GROUPS = {
    'service_control': ('OpenSCManager', 'OpenService', 'CreateService',
                        'StartService', 'ControlService', 'ChangeService',
                        'QueryService', 'DeleteService'),
    'driver_handle_or_ipc': ('DeviceIoControl', 'CreateFile', 'NtDeviceIoControlFile'),
    'registry': ('RegOpen', 'RegCreate', 'RegLoad', 'RegSave', 'RegSet',
                 'RegRestore', 'RegReplace', 'RegDelete', 'RegUnLoad'),
    'reboot': ('ExitWindowsEx', 'InitiateSystemShutdown'),
    'network': ('WinHttp', 'WinInet', 'InternetOpen', 'InternetConnect'),
}


class PEError(ValueError):
    pass


class PEView:
    def __init__(self, data):
        self.data = data
        if len(data) > MAX_PE or len(data) < 64 or data[:2] != b'MZ':
            raise PEError('MZ ausente ou PE fora do limite')
        pe = self.u32(0x3c)
        if pe < 64 or pe + 24 > len(data) or data[pe:pe + 4] != b'PE\0\0':
            raise PEError('Assinatura PE inválida')
        self.machine = self.u16(pe + 4)
        nsections = self.u16(pe + 6)
        optional_size = self.u16(pe + 20)
        opt = pe + 24
        if nsections > 96 or opt + optional_size > len(data):
            raise PEError('COFF ou OptionalHeader truncado')
        magic = self.u16(opt)
        if magic not in (0x10b, 0x20b):
            raise PEError('Formato PE desconhecido')
        self.pe64 = magic == 0x20b
        directory_start = 112 if self.pe64 else 96
        if optional_size < directory_start:
            raise PEError('OptionalHeader incompleto')
        self.size_headers = self.u32(opt + 60)
        self.entry_rva = self.u32(opt + 16)
        self.dll_characteristics = self.u16(opt + 70)
        ndirs = self.u32(opt + directory_start - 4)
        self.directories = [
            (self.u32(opt + directory_start + i * 8),
             self.u32(opt + directory_start + i * 8 + 4))
            for i in range(min(ndirs, 16, (optional_size - directory_start) // 8))
        ]
        self.sections = []
        start = opt + optional_size
        for i in range(nsections):
            at = start + i * 40
            self.check(at, 40)
            name = data[at:at + 8].split(b'\0', 1)[0].decode('ascii', 'replace')
            vsize, rva, rawsize, rawat = struct.unpack_from('<IIII', data, at + 8)
            if rawsize:
                self.check(rawat, rawsize)
            self.sections.append({
                'name': name, 'rva': rva, 'virtual_size': vsize,
                'offset': rawat, 'raw_size': rawsize,
            })

    def check(self, offset, size):
        if offset < 0 or size < 0 or offset > len(self.data) or size > len(self.data) - offset:
            raise PEError('Acesso fora dos limites')

    def u16(self, at):
        self.check(at, 2)
        return struct.unpack_from('<H', self.data, at)[0]

    def u32(self, at):
        self.check(at, 4)
        return struct.unpack_from('<I', self.data, at)[0]

    def u64(self, at):
        self.check(at, 8)
        return struct.unpack_from('<Q', self.data, at)[0]

    def rva_offset(self, rva, size=1):
        for sec in self.sections:
            delta = rva - sec['rva']
            if 0 <= delta < max(sec['virtual_size'], sec['raw_size']):
                if delta + size > sec['raw_size']:
                    raise PEError('RVA em memória virtual sem bytes físicos')
                offset = sec['offset'] + delta
                self.check(offset, size)
                return offset
        if 0 <= rva < self.size_headers:
            self.check(rva, size)
            return rva
        raise PEError('RVA sem seção correspondente')

    def asciiz(self, offset, max_size=256):
        self.check(offset, 1)
        end = self.data.find(b'\0', offset, min(len(self.data), offset + max_size + 1))
        if end < 0:
            raise PEError('String não terminada')
        return self.data[offset:end].decode('ascii', 'replace')

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def imports(self):
        rva, size = self.directory(1)
        if not rva or not size:
            return []
        width = 8 if self.pe64 else 4
        high_bit = (1 << 63) if self.pe64 else (1 << 31)
        result = []
        for i in range(min(MAX_DLLS, size // 20)):
            at = self.rva_offset(rva + i * 20, 20)
            oft, timestamp, forward, name_rva, iat = struct.unpack_from('<IIIII', self.data, at)
            if (oft, timestamp, forward, name_rva, iat) == (0, 0, 0, 0, 0):
                break
            name = self.asciiz(self.rva_offset(name_rva))
            names = []
            for j in range(MAX_FUNCTIONS):
                t = self.rva_offset((oft or iat) + j * width, width)
                value = self.u64(t) if self.pe64 else self.u32(t)
                if not value:
                    break
                if value & high_bit:
                    names.append('#' + str(value & 0xffff))
                else:
                    names.append(self.asciiz(self.rva_offset(value + 2)))
            else:
                raise PEError('Excesso de funções importadas')
            result.append({'dll': name, 'functions': names})
        else:
            raise PEError('Excesso de DLLs ou importações sem terminador')
        return result

    def resources(self, depth=2):
        rva, size = self.directory(2)
        if not rva or not size:
            return []
        def resource_offset(relative, length):
            if relative < 0 or relative + length > size:
                raise PEError('Recurso fora do diretório')
            return self.rva_offset(rva + relative, length)
        def resource_name(number):
            if not (number & 0x80000000):
                return str(number)
            at = resource_offset(number & 0x7fffffff, 2)
            length = self.u16(at)
            if length > 128:
                raise PEError('Nome do recurso excessivo')
            at = resource_offset((number & 0x7fffffff) + 2, length * 2)
            return self.data[at:at + length * 2].decode('utf-16le', 'replace')
        result = []
        visited = set()
        def walk(relative, trail, level):
            if level > 4 or relative in visited:
                return
            visited.add(relative)
            at = resource_offset(relative, 16)
            named, numeric = struct.unpack_from('<HH', self.data, at + 12)
            if named + numeric > MAX_RESOURCES:
                raise PEError('Recurso com entradas excessivas')
            for i in range(named + numeric):
                if len(result) >= MAX_RESOURCES:
                    raise PEError('Limite de recursos excedido')
                at = resource_offset(relative + 16 + i * 8, 8)
                label, pointer = struct.unpack_from('<II', self.data, at)
                path = trail + [resource_name(label)]
                rel = pointer & 0x7fffffff
                if pointer & 0x80000000:
                    walk(rel, path, level + 1)
                    continue
                at = resource_offset(rel, 16)
                content_rva, length, _, _ = struct.unpack_from('<IIII', self.data, at)
                if length > MAX_PE:
                    raise PEError('Tamanho de recurso excedido')
                payload_at = self.rva_offset(content_rva, length)
                payload = self.data[payload_at:payload_at + length]
                item = {
                    'path': path, 'file_offset': payload_at, 'size': length,
                    'sha256': hashlib.sha256(payload).hexdigest(),
                    'magic': 'MZ' if payload[:2] == b'MZ' else 'other',
                }
                if payload[:2] == b'MZ':
                    try:
                        item['embedded_pe'] = PEView(payload).summary(
                            include_resources=depth > 1, depth=depth - 1)
                    except PEError as exc:
                        item['pe_candidate_error'] = str(exc)
                result.append(item)
        walk(0, [], 0)
        return result

    def summary(self, include_resources=True, depth=2):
        imports = self.imports()
        functions = {f for lib in imports for f in lib['functions']}
        groups = {
            key: sorted(fn for fn in functions if any(fn.startswith(prefix) for prefix in prefixes))
            for key, prefixes in API_GROUPS.items()
        }
        groups = {key: value for key, value in groups.items() if value}
        refs = [name for name in DRIVERS if name.encode('ascii') in self.data
                or name.encode('utf-16le') in self.data]
        result = {
            'format': 'PE32+' if self.pe64 else 'PE32',
            'machine': '0x%04x' % self.machine,
            'entry_rva': '0x%x' % self.entry_rva,
            'dll_characteristics': '0x%04x' % self.dll_characteristics,
            'sections': self.sections, 'imports': imports,
            'api_groups': groups, 'driver_filename_string_references': refs,
            'interpretation': 'Importações e strings não comprovam execução, carregamento de driver ou IOCTL.',
        }
        if include_resources:
            result['resources'] = self.resources(depth=depth)
        return result


def inspect_archive(path):
    archive_path = pathlib.Path(path)
    # Hash em fluxo: não carregar o ZIP inteiro em memória.
    digest = hashlib.sha256()
    with archive_path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    result = {
        'schema': 'rea-structural-v1', 'source': archive_path.name,
        'sha256': digest.hexdigest(), 'artifacts': [], 'warnings': [],
    }
    budget = 0
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ValueError('ZIP excede limite de entradas')
        for info in infos:
            if info.is_dir():
                continue
            name = info.filename.replace('\\', '/')
            if (name.startswith('/') or ':' in name or '..' in name.split('/')
                    or info.flag_bits & 1):
                result['warnings'].append('Entrada ignorada por segurança: ' + info.filename)
                continue
            budget += info.file_size
            if info.file_size > MAX_PE or budget > MAX_TOTAL:
                raise ValueError('ZIP excede limites de descompressão')
            digest = hashlib.sha256()
            contents = bytearray() if name.lower().endswith(('.exe', '.sys', '.dll')) else None
            with archive.open(info) as source:
                seen = 0
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    seen += len(block)
                    if seen > info.file_size:
                        raise ValueError('Tamanho ZIP inconsistente')
                    digest.update(block)
                    if contents is not None:
                        contents.extend(block)
            if contents is None:
                continue
            artifact = {
                'path': info.filename, 'size': info.file_size,
                'sha256': digest.hexdigest(),
            }
            try:
                artifact['pe'] = PEView(bytes(contents)).summary()
            except PEError as exc:
                artifact['parse_error'] = str(exc)
            result['artifacts'].append(artifact)
    return result


def inspect_file(path):
    data = pathlib.Path(path).read_bytes()
    return {
        'schema': 'rea-structural-v1',
        'source': pathlib.Path(path).name, 'warnings': [],
        'artifacts': [{
            'path': pathlib.Path(path).name, 'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'pe': PEView(data).summary(),
        }],
    }


def markdown_report(report):
    lines = [
        '# Mapa estrutural REA — relatório automatizado', '',
        'Inspeção estática, sem execução. Importação não prova chamada em runtime.',
        '', 'Fonte: ' + report['source'], '',
    ]
    for a in report['artifacts']:
        p = a.get('pe')
        if not p:
            continue
        lines.extend([
            '## ' + a['path'], '',
            '- SHA-256: ' + a['sha256'],
            '- Formato: ' + p['format'] + ' (' + p['machine'] + ')',
            '- DLLs importadas: ' + str(len(p['imports'])),
            '- Recursos: ' + str(len(p.get('resources', []))), '',
        ])
        for group, functions in sorted(p['api_groups'].items()):
            lines.append('- ' + group + ' (importação): ' + ', '.join(functions))
        if p['driver_filename_string_references']:
            lines.append('- Nomes de driver em strings (não confirmam instalação): ' +
                         ', '.join(p['driver_filename_string_references']))
        def nested(resources, prefix=''):
            for r in resources:
                if 'embedded_pe' in r:
                    child = r['embedded_pe']
                    path = prefix + '/'.join(r['path'])
                    lines.append('- PE embutido: ' + path +
                                 ' | bytes=' + str(r['size']) +
                                 ' | sha256=' + r['sha256'] +
                                 ' | dlls=' + str(len(child['imports'])))
                    nested(child.get('resources', []), path + ' > ')
        nested(p.get('resources', []))
        lines.append('')
    lines.extend([
        '## Limitações', '',
        '- APIs e nomes são dados estáticos: serviços/driver não foram carregados.',
        '- Nenhum IOCTL, objeto Device ou contrato IRP foi demonstrado.',
        '- UPX não é descompactado por este analisador.',
        '- Windows 7 SP1 x86/x64 ainda exige testes em VMs.', '',
    ])
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--archive', help='ZIP local (somente leitura)')
    group.add_argument('--pe', help='PE local (somente leitura)')
    parser.add_argument('--json', dest='json_path', help='Saída JSON')
    parser.add_argument('--markdown', help='Saída Markdown')
    args = parser.parse_args(argv)
    try:
        report = inspect_archive(args.archive) if args.archive else inspect_file(args.pe)
        rendered = json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + '\n'
        if args.json_path:
            pathlib.Path(args.json_path).write_text(rendered, encoding='utf-8')
        else:
            sys.stdout.write(rendered)
        if args.markdown:
            pathlib.Path(args.markdown).write_text(markdown_report(report), encoding='utf-8')
        return 2 if report['warnings'] else 0
    except (PEError, ValueError, OSError, zipfile.BadZipFile, RuntimeError) as exc:
        print('Falha na análise estrutural: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
