# Usage: python check.py path/to/eu.exe (needs gcc on PATH)
# Differential test: the original C, compiled, against the pseudocode Euphoria produced from it.
import os, re, subprocess, sys, tempfile

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
    'f_strlen': 'str',
}
VALUES = [-1000, -37, -9, -5, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 19, 20, 21, 27, 100, 97, 1000]

def run(args, timeout=60):
    return subprocess.run(args, capture_output=True, text=True, cwd=HERE, timeout=timeout)

def output_lines(exe):
    result = run([exe])
    if result.returncode:
        raise RuntimeError(f'{exe} exited with {result.returncode}: {result.stderr}')
    lines = result.stdout.splitlines()
    if not lines:
        raise RuntimeError(f'{exe} produced no results')
    return lines

def compare_outputs(expected, got):
    if len(got) != len(expected):
        raise RuntimeError(f'line count {len(got)} vs {len(expected)}')
    bad = {}
    for e, g in zip(expected, got):
        if e != g:
            bad.setdefault(e.split()[0], []).append((e, g))
    return bad

def driver(prefix):
    out = []
    for name, sig in FUNCS.items():
        if sig == 'ptr':
            out.append(f'{{ int d[5] = {{3,-4,5,9,100}}; for (int n = 0; n < 6; n++) printf("{name} %d %d\\n", n, (int){prefix}{name}((void*)d, n)); }}')
            continue
        if sig == 'str':
            out.append(f'{{ const char *t[3] = {{"", "abc", "hello world"}}; for (int n = 0; n < 3; n++) printf("{name} %d %d\\n", n, (int){prefix}{name}((void*)t[n])); }}')
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

def build_original(opt, bits):
    exe = os.path.join(OUT, f'orig_{opt}_{bits}.exe')
    # The driver stays in a separate unit so inlining cannot hide the routines from the decompiler.
    obj = os.path.join(OUT, f'funcs_{opt}_{bits}.o')
    r = run(['gcc', f'-m{bits}', f'-{opt}', '-c', 'funcs.c', '-o', obj, '-fno-stack-protector', '-fno-tree-switch-conversion', '-fno-jump-tables' if bits == 32 else '-fjump-tables', '-fno-pic', '-fno-asynchronous-unwind-tables', '-fomit-frame-pointer' if opt != 'O0' else '-fno-omit-frame-pointer'])
    if r.returncode: raise SystemExit(r.stderr)
    protos = ''
    for name, sig in FUNCS.items():
        if sig == 'ptr': protos += f'int {name}(void*,int);\n'
        elif sig == 'str': protos += f'int {name}(void*);\n'
        else:
            ret = sig[:sig.index('(')]
            protos += f'{ret} {name}({sig[sig.index("(")+1:-1]});\n'
    drv = os.path.join(OUT, f'orig_drv_{opt}_{bits}.c')
    open(drv, 'w').write('#include <stdio.h>\n#include <stdint.h>\n' + protos + VDECL + 'int main(void){\n' + '\n'.join(driver('')) + '\nreturn 0;}\n')
    r = run(['gcc', f'-m{bits}', '-O0', drv, obj, '-o', exe])
    if r.returncode: raise SystemExit(r.stderr)
    return exe

def decompile(exe):
    texts = {}
    for name in [*FUNCS, 'f_fill']:
        r = run([EU, 'decompile', exe, name])
        if r.returncode or not r.stdout.strip():
            raise RuntimeError(f'could not decompile {name}: {r.stderr}')
        texts[name] = r.stdout
    return texts

def main():
    total_fail = 0
    configs = [('O0', 64), ('O1', 64), ('O2', 64), ('Os', 64)]
    for opt, bits in configs:
        exe = build_original(opt, bits)
        expected = output_lines(exe)
        texts = decompile(exe)
        c = '#include <stdio.h>\n#include <stdint.h>\n#include <math.h>\nstatic int32_t __mulhs(int32_t a,int32_t b){return (int64_t)a*b>>32;}\nstatic uint32_t __mulhu(uint32_t a,uint32_t b){return (uint64_t)a*b>>32;}\n'
        for name, text in texts.items():
            sig = re.search(r'^\S.*\b' + name + r'\(.*\)$', text, re.M)
            if sig: c += sig.group(0) + ';\n'
        for name, text in texts.items():
            c += text + '\n'
        c += VDECL + 'int main(void){\n' + '\n'.join(driver('')) + '\nreturn 0;}\n'
        path = os.path.join(OUT, f'dec_{opt}_{bits}.c')
        open(path, 'w').write(c)
        exe2 = os.path.join(OUT, f'dec_{opt}_{bits}.exe')
        r = run(['gcc', f'-m{bits}', '-O0', '-fwrapv', '-w', '-fpermissive', path, '-o', exe2])
        if r.returncode:
            print(f'== {opt}/{bits}: pseudocode did not compile')
            print('\n'.join(r.stderr.splitlines()[:25]))
            total_fail += 1
            continue
        got = output_lines(exe2)
        bad = compare_outputs(expected, got)
        ok = [n for n in FUNCS if n not in bad]
        print(f'== {opt}/{bits}: {len(ok)}/{len(FUNCS)} routines match on {len(expected)} results')
        for n, cases in bad.items():
            print('  MISMATCH', n, cases[0])
            total_fail += 1
    sys.exit(1 if total_fail else 0)

if __name__ == '__main__':
    EU = os.path.abspath(sys.argv[1])
    with tempfile.TemporaryDirectory(prefix='euphoria_check_') as OUT:
        try:
            main()
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            raise SystemExit(str(error))
