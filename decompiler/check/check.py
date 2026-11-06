# Usage: python check.py path/to/eu.exe [--compiler gcc] [--no-boundary]
# Differential test: the original C, compiled, against the pseudocode Euphoria produced from it.
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EU = None
OUT = None

FUNCS = {
    'f_add': 'int(int,int)', 'f_abs': 'int(int)', 'f_max3': 'int(int,int,int)', 'f_sum': 'int(int)',
    'f_classify': 'int(int)', 'f_collatz': 'int(int)', 'f_gcd': 'int(int,int)',
    'f_udiv': 'unsigned(unsigned)', 'f_sdiv': 'int(int)', 'f_switch': 'int(int)', 'f_range': 'int(int)',
    'f_nested': 'int(int,int)', 'f_bits': 'unsigned(unsigned)', 'f_narrow': 'int8_t(int8_t,int8_t)',
    'f_wide': 'int64_t(int64_t,int)', 'f_early': 'int(int,int)', 'f_dowhile': 'int(int)',
    'f_cont': 'int(int)', 'f_callee': 'int(int)',
    'f_many': 'int(int,int,int,int,int,int)', 'f_callmany': 'int(int)', 'f_ptr': 'ptr', 'f_local': 'int(int)',
    'f_strlen': 'str', 'f_pair': 'pair', 'f_scale': 'scale', 'f_fib': 'int(int)',
    'f_i64div': 'int64_t(int64_t,int64_t)', 'f_uadd': 'unsigned(unsigned,unsigned)',
}
VALUES = [-1000, -37, -9, -5, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 19, 20, 21, 27, 100, 97, 1000]

GNU_CONFIGS = [('O0', 64), ('O1', 64), ('O2', 64), ('Os', 64), ('O0', 32), ('O2', 32)]
MSVC_CONFIGS = [('Od', 64), ('O2', 64)]
MSVC_OPT = {'O0': '/Od', 'O1': '/O1', 'O2': '/O2', 'Os': '/O1', 'Od': '/Od'}


def run(args, timeout=60):
    return subprocess.run(args, capture_output=True, text=True, cwd=HERE, timeout=timeout)


class GNU:
    def __init__(self, cc):
        self.cc = cc
        self.name = os.path.basename(cc).lower().removesuffix('.exe')
        self.configs = GNU_CONFIGS

    def _flags(self, opt, bits):
        flags = [f'-m{bits}', f'-{opt}', '-fno-stack-protector', '-fno-pic',
                 '-fno-asynchronous-unwind-tables']
        if self.name == 'gcc':
            # GCC can turn a switch into a different shape than clang; keep both predictable.
            flags.append('-fno-tree-switch-conversion')
        if bits == 32:
            flags.append('-fno-jump-tables')
        return flags

    def object_cmd(self, bits, opt, source, out):
        return [self.cc, *self._flags(opt, bits), '-c', source, '-o', out]

    def driver_cmd(self, bits, source, obj, out):
        return [self.cc, f'-m{bits}', '-O0', source, obj, '-o', out]

    def simple_cmd(self, bits, source, out):
        return [self.cc, f'-m{bits}', source, '-o', out]


class MSVC:
    def __init__(self, cc):
        self.cc = cc
        self.name = 'cl'
        self.configs = MSVC_CONFIGS

    def object_cmd(self, bits, opt, source, out):
        return [self.cc, '/nologo', '/c', MSVC_OPT[opt], f'/Fo{out}', source,
                '/D_CRT_SECURE_NO_WARNINGS']

    def driver_cmd(self, bits, source, obj, out):
        return [self.cc, '/nologo', '/Od', source, obj, f'/Fe:{out}']

    def simple_cmd(self, bits, source, out):
        return [self.cc, '/nologo', '/Od', source, f'/Fe:{out}']


def toolchain(path):
    name = os.path.basename(path).lower().removesuffix('.exe')
    return MSVC(path) if name == 'cl' else GNU(path)


def probe(compiler, bits):
    """Returns None when the compiler can build an executable for these bits, else a reason."""
    source = os.path.join(OUT, f'probe_{compiler.name}_{bits}.c')
    exe = os.path.join(OUT, f'probe_{compiler.name}_{bits}.exe')
    with open(source, 'w') as file:
        file.write('int main(void){return 0;}\n')
    try:
        result = run(compiler.simple_cmd(bits, source, exe))
    except OSError as error:
        return str(error)
    if result.returncode == 0:
        return None
    if bits == 32:
        return 'no 32-bit C runtime (install an i686 or multilib toolchain)'
    first = next((line.strip() for line in result.stderr.splitlines() if line.strip()), '')
    return first or f'{compiler.name} could not build a simple program'


def driver(prefix):
    out = []
    for name, sig in FUNCS.items():
        if sig == 'ptr':
            out.append(f'{{ int d[5] = {{3,-4,5,9,100}}; for (int n = 0; n < 6; n++) printf("{name} %d %d\\n", n, (int){prefix}{name}((void*)d, n)); }}')
            continue
        if sig == 'str':
            out.append(f'{{ const char *t[3] = {{"", "abc", "hello world"}}; for (int n = 0; n < 3; n++) printf("{name} %d %d\\n", n, (int){prefix}{name}((void*)t[n])); }}')
            continue
        if sig == 'pair':
            out.append(f'{{ struct {{ int a, b; }} p = {{7, -3}}; for (int k = 0; k < 3; k++) printf("{name} %d %d\\n", k, (int){prefix}{name}((void*)&p, k)); }}')
            continue
        if sig == 'scale':
            out.append(f'{{ int d[5] = {{3,-4,5,9,100}}; for (int n = 0; n < 6; n++) {{ int c[5]; for (int j = 0; j < 5; j++) c[j] = d[j]; {prefix}{name}((void*)c, n, 2); printf("{name} %d %d %d\\n", n, c[0], c[4]); }} }}')
            continue
        if name == 'f_fib':
            out.append(f'for (int n = 0; n < 13; n++) printf("{name} %d %d\\n", n, (int){prefix}{name}(n));')
            continue
        args = sig[sig.index('(') + 1:-1].split(',')
        loops = ''
        call = []
        fmt = []
        for i, a in enumerate(args):
            loops += f'for (int i{i} = 0; i{i} < {len(VALUES) if len(args) < 3 else 5}; i{i}++) '
            call.append(f'({a})V[i{i}]')
            fmt.append(f'V[i{i}]')
        vs = ', '.join(fmt)
        out.append(f'{loops}printf("{name} {" ".join(["%d"] * len(args))} %lld\\n", {vs}, (long long)({sig[:sig.index("(")]}){prefix}{name}({", ".join(call)}));')
    return out


VDECL = 'static const int V[] = {' + ','.join(map(str, VALUES)) + '};\n'


def prototypes():
    protos = ''
    for name, sig in FUNCS.items():
        if sig in ('ptr', 'pair'):
            protos += f'int {name}(void*,int);\n'
        elif sig == 'str':
            protos += f'int {name}(void*);\n'
        elif sig == 'scale':
            protos += f'void {name}(void*,int,int);\n'
        else:
            ret = sig[:sig.index('(')]
            protos += f'{ret} {name}({sig[sig.index("(")+1:-1]});\n'
    return protos


def build_original(compiler, opt, bits):
    stem = f'{compiler.name}_{opt}_{bits}'
    obj = os.path.join(OUT, f'funcs_{stem}.obj')
    result = run(compiler.object_cmd(bits, opt, os.path.join(HERE, 'funcs.c'), obj))
    if result.returncode:
        raise RuntimeError(f'{compiler.name}/{opt}/{bits} could not build funcs.c: {result.stderr}')
    drv = os.path.join(OUT, f'drv_{stem}.c')
    with open(drv, 'w') as file:
        file.write('#include <stdio.h>\n#include <stdint.h>\n' + prototypes() + VDECL +
                   'int main(void){\n' + '\n'.join(driver('')) + '\nreturn 0;}\n')
    exe = os.path.join(OUT, f'orig_{stem}.exe')
    result = run(compiler.driver_cmd(bits, drv, obj, exe))
    if result.returncode:
        raise RuntimeError(f'{compiler.name}/{opt}/{bits} could not link the driver: {result.stderr}')
    return exe


def decompile(exe):
    texts = {}
    for name in [*FUNCS, 'f_fill']:
        result = run([EU, 'decompile', exe, name])
        if result.returncode or not result.stdout.strip():
            raise RuntimeError(f'could not decompile {name}: {result.stderr}')
        texts[name] = result.stdout
    return texts


def output_lines(exe):
    result = run([exe])
    if result.returncode:
        raise RuntimeError(f'{exe} exited with {result.returncode}: {result.stderr}')
    lines = result.stdout.splitlines()
    if not lines:
        raise RuntimeError(f'{exe} produced no results')
    return lines


def run_program(exe):
    result = run([exe])
    return result.stdout.splitlines(), result.returncode


def compare_outputs(expected, got):
    if len(got) != len(expected):
        for index, (left, right) in enumerate(zip(expected, got)):
            if left != right:
                raise RuntimeError(f'line {index + 1}: expected {left!r}, got {right!r}')
        raise RuntimeError(f'got {len(got)} of {len(expected)} results')
    bad = {}
    for e, g in zip(expected, got):
        if e != g:
            bad.setdefault(e.split()[0], []).append((e, g))
    return bad


def write_pseudocode(texts, path):
    c = ('#include <stdio.h>\n#include <stdint.h>\n#include <string.h>\n#include <math.h>\n'
         'static int32_t __mulhs(int32_t a,int32_t b){return (int64_t)a*b>>32;}\n'
         'static uint32_t __mulhu(uint32_t a,uint32_t b){return (uint64_t)a*b>>32;}\n')
    for name, text in texts.items():
        sig = re.search(r'^\S.*\b' + name + r'\(.*\)$', text, re.M)
        if sig:
            c += sig.group(0) + ';\n'
    for text in texts.values():
        c += text + '\n'
    c += VDECL + 'int main(void){\nsetvbuf(stdout, NULL, _IONBF, 0);\n' + \
        '\n'.join(driver('')) + '\nreturn 0;}\n'
    with open(path, 'w') as file:
        file.write(c)


def symbol_starts(nm, exe):
    result = run([nm, '--defined-only', exe])
    if result.returncode:
        return {}
    symbols = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ('T', 't'):
            symbols[int(parts[0], 16)] = parts[2].lstrip('_')
    return symbols


def boundary_report(eu, exe):
    """Compares stripped-binary discovery against the symbol starts of the unstripped fixture."""
    nm, strip = shutil.which('nm'), shutil.which('strip')
    if not nm or not strip:
        return None
    stripped = exe + '.stripped.exe'
    shutil.copyfile(exe, stripped)
    if run([strip, stripped]).returncode:
        return None
    symbols = symbol_starts(nm, exe)
    if not symbols:
        return None
    result = run([eu, '--json', 'functions', stripped])
    if result.returncode:
        return None
    starts = {function['va'] for function in json.loads(result.stdout)}
    truth = {address for address, name in symbols.items() if name.startswith('f_')}
    known = set(symbols)
    return {
        'truth': len(truth),
        'missing': sorted(truth - starts),
        'extras': len(starts - known),
        'precision': len(starts & known) / len(starts) if starts else 0.0,
    }


def check_config(compiler, opt, bits, boundary=True):
    label = f'{compiler.name}/{opt}/{bits}'
    exe = build_original(compiler, opt, bits)
    expected = output_lines(exe)

    if boundary:
        report = boundary_report(os.path.abspath(EU), exe)
        if report is None:
            print(f'== {label}: boundary check skipped (nm/strip unavailable)')
        elif report['missing']:
            print(f"== {label}: boundary check found {report['missing']} missing of "
                  f"{report['truth']} routines (precision {report['precision']:.0%})")
        else:
            print(f"== {label}: boundaries {report['truth']}/{report['truth']} routines, "
                  f"precision {report['precision']:.0%}, {report['extras']} extra start(s)")

    texts = decompile(exe)
    source = os.path.join(OUT, f'dec_{compiler.name}_{opt}_{bits}.c')
    write_pseudocode(texts, source)
    dec = os.path.join(OUT, f'dec_{compiler.name}_{opt}_{bits}.exe')
    cc = shutil.which('gcc') or shutil.which('clang')
    if cc is None:
        print(f'== {label}: no gcc or clang available to compile the pseudocode')
        return 1
    result = run([cc, f'-m{bits}', '-O0', '-fwrapv', '-fpermissive', '-w', source, '-o', dec])
    if result.returncode:
        print(f'== {label}: pseudocode did not compile')
        print('\n'.join(result.stderr.splitlines()[:25]))
        return 1

    got, code = run_program(dec)
    try:
        bad = compare_outputs(expected, got)
    except RuntimeError as error:
        print(f'== {label}: {error}' + (f' (exit code {code:#x})' if code else ''))
        return 1
    if code:
        print(f'== {label}: the decompiled program crashed with {code:#x}')
        return 1

    ok = [name for name in FUNCS if name not in bad]
    print(f'== {label}: {len(ok)}/{len(FUNCS)} routines match on {len(expected)} results')
    for name, cases in bad.items():
        print('  MISMATCH', name, cases[0])
    return len(bad)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Differential decompiler check')
    parser.add_argument('eu', help='path to the eu executable')
    parser.add_argument('--compiler', action='append',
                        help='compiler to use (gcc, clang, cl); repeatable; default: all found')
    parser.add_argument('--no-boundary', action='store_true',
                        help='skip the stripped-binary function-boundary check')
    args = parser.parse_args(argv)

    global EU, OUT
    EU = os.path.abspath(args.eu)
    names = args.compiler or ['gcc', 'clang', 'cl']
    available = [toolchain(path) for path in (shutil.which(name) for name in names) if path]

    failures = 0
    ran = 0
    probes = {}
    with tempfile.TemporaryDirectory(prefix='euphoria_check_') as out:
        OUT = out
        if not available:
            print('no C compiler found (tried ' + ', '.join(names) + ')')
            return 2
        for compiler in available:
            for opt, bits in compiler.configs:
                key = (compiler.name, bits)
                if key not in probes:
                    probes[key] = probe(compiler, bits)
                reason = probes[key]
                if reason:
                    print(f'== {compiler.name}/{opt}/{bits}: skipped ({reason})')
                    continue
                ran += 1
                try:
                    failures += check_config(compiler, opt, bits, not args.no_boundary)
                except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                    print(f'== {compiler.name}/{opt}/{bits}: {error}')
                    failures += 1
    if ran == 0:
        print('no toolchain could build a test program')
        return 2
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
