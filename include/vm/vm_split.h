#ifndef CRYPTO_VM_SPLIT_H
#define CRYPTO_VM_SPLIT_H

static const char VM_SPLIT_SCRIPT[] = R"vm_split(
import sys, ast, os, tempfile, subprocess

def genexpr_to_listcomp(source):
    tree = ast.parse(source)
    class Transformer(ast.NodeTransformer):
        def visit_GeneratorExp(self, node):
            self.generic_visit(node)
            return ast.ListComp(elt=node.elt, generators=node.generators)
    tree = Transformer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)

def extract_defs(tree):
    funcs = []
    others = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            funcs.append(node)
        else:
            others.append(node)
    return funcs, others

def build_full_name_map(orig_body, obf_body):
    # Returns (name_map, attr_map) — attr_map only has function/method/class names
    m = {}
    a = {}
    for on, fn in zip(orig_body, obf_body):
        if isinstance(on, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if on.name != fn.name:
                m[on.name] = fn.name
                a[on.name] = fn.name
            for op, fp in zip(on.args.args, fn.args.args):
                if op.arg != fp.arg:
                    m[op.arg] = fp.arg
            for op, fp in zip(on.args.kwonlyargs, fn.args.kwonlyargs):
                if op.arg != fp.arg:
                    m[op.arg] = fp.arg
        elif isinstance(on, ast.ClassDef):
            if on.name != fn.name:
                m[on.name] = fn.name
                a[on.name] = fn.name
            orig_methods = [m for m in on.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
            obf_methods = [m for m in fn.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
            for oi, fi in zip(orig_methods, obf_methods):
                if oi.name != fi.name:
                    m[oi.name] = fi.name
                    a[oi.name] = fi.name
                for op, fp in zip(oi.args.args, fi.args.args):
                    if op.arg != fp.arg:
                        m[op.arg] = fp.arg
                for op, fp in zip(oi.args.kwonlyargs, fi.args.kwonlyargs):
                    if op.arg != fp.arg:
                        m[op.arg] = fp.arg
    return m, a

def build_global_name_map(orig_others, obf_others):
    # Collect original single-target Assign names in order
    orig_simple = []
    for n in orig_others:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            orig_simple.append(n.targets[0].id)

    # Collect obfuscated single-target Assign names in order
    obf_simple = []
    for n in obf_others:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            obf_simple.append(n.targets[0].id)

    # Map by position, only if names differ
    m = {}
    for o, f in zip(orig_simple, obf_simple):
        if o != f:
            m[o] = f
    return m

def apply_rename(source, name_map, attr_map=None):
    if not name_map:
        return source
    if attr_map is None:
        attr_map = name_map
    tree = ast.parse(source)
    # Collect imported names — they should never be renamed
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                imported.add(alias.asname or alias.name)
    class Renamer(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in name_map \
                    and node.id not in imported:
                node.id = name_map[node.id]
            return node
        def visit_Attribute(self, node):
            if node.attr in attr_map:
                node.attr = attr_map[node.attr]
            self.generic_visit(node)
            return node
        def visit_keyword(self, node):
            if node.arg is not None and node.arg in name_map:
                node.arg = name_map[node.arg]
            self.generic_visit(node)
            return node
    tree = Renamer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)

def obfuscate_source(obf_script_path, source, techniques):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f_in = f.name
        f.write(source)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f_out = f.name
    try:
        with open(f_in) as fi, open(f_out, 'w') as fo:
            r = subprocess.run(['python3', obf_script_path, techniques],
                               stdin=fi, stdout=fo, stderr=subprocess.PIPE)
        if r.returncode != 0:
            err = r.stderr.decode() if r.stderr else 'unknown error'
            raise RuntimeError(f'obfuscation failed: {err}')
        with open(f_out) as f:
            return f.read()
    finally:
        os.unlink(f_in)
        os.unlink(f_out)

def extract_imports(tree):
    return [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]

def pipeline(orig_source, obf_script_path, techniques=None):
    orig_tree = ast.parse(orig_source)
    orig_funcs, orig_others = extract_defs(orig_tree)

    # Separate imports from module-level code — imports must go to exec
    # part so they are available when funcenc decrypts functions at runtime.
    orig_imports = [n for n in orig_others if isinstance(n, (ast.Import, ast.ImportFrom))]
    orig_module = [n for n in orig_others if not isinstance(n, (ast.Import, ast.ImportFrom))]

    func_source = ast.unparse(ast.Module(body=orig_funcs, type_ignores=[])) if orig_funcs else ''
    import_source = ast.unparse(ast.Module(body=orig_imports, type_ignores=[])) if orig_imports else ''
    module_source = ast.unparse(ast.Module(body=orig_module, type_ignores=[])) if orig_module else ''

    full_source = func_source
    if import_source:
        full_source += '\n' + import_source
    if module_source:
        full_source += '\n' + module_source

    full_source = genexpr_to_listcomp(full_source)

    # Step 1: Obfuscate FULL source with rename ONLY if techniques specified.
    #         This builds name mapping for consistent naming between exec and VM.
    #         Skip rename entirely when no obfuscation requested.
    if techniques:
        rename_source = obfuscate_source(obf_script_path, full_source, 'rename')
    else:
        rename_source = full_source

    rename_tree = ast.parse(rename_source)
    rename_funcs, rename_others = extract_defs(rename_tree)

    # Separate imports from other module-level code in the rename output
    rename_imports = [n for n in rename_others if isinstance(n, (ast.Import, ast.ImportFrom))]
    rename_module = [n for n in rename_others if not isinstance(n, (ast.Import, ast.ImportFrom))]

    # Build name map from original → rename-only (ensures consistent naming)
    name_map, attr_map = build_full_name_map(orig_funcs, rename_funcs)
    name_map.update(build_global_name_map(orig_module, rename_module))

    # Step 2: Apply remaining techniques (all except rename) to the
    #         ALREADY-RENAMED func defs, so function/param names stay
    #         consistent with the name_map from Step 1.
    exec_body_imports = list(rename_imports)  # imports go directly to exec part
    if rename_funcs:
        renamed_func_source = ast.unparse(ast.Module(body=rename_funcs, type_ignores=[]))
        renamed_func_source = genexpr_to_listcomp(renamed_func_source)

        # Strip 'rename' (and expand 'all') so we never double-rename
        tech_list = [t.strip() for t in techniques.split(',') if t.strip()]
        if 'all' in tech_list:
            remaining_techs = 'cleanup,strings,vstrings,flow,aflow,opaque,mutate,mba,junk,apihash,funcenc'
        else:
            remaining_techs = ','.join(t for t in tech_list if t != 'rename')

        if remaining_techs:
            obf_func_source = obfuscate_source(obf_script_path, renamed_func_source, remaining_techs)
        else:
            obf_func_source = renamed_func_source

        obf_func_tree = ast.parse(obf_func_source)
        obf_imports = extract_imports(obf_func_tree)
        obf_funcs, obf_others = extract_defs(obf_func_tree)
        # Imports from func obfuscation come first, then original renamed imports,
        # then funcs (funcenc may add new stubs that reference imports)
        exec_body = obf_imports + exec_body_imports + obf_others + obf_funcs
    else:
        exec_body = exec_body_imports
    exec_source = ast.unparse(ast.Module(body=exec_body, type_ignores=[])) if exec_body else ''

    # Step 3: VM source = rename-only module-level code (no flow/junk/mutate),
    #         EXcluding imports which were moved to exec part.
    vm_source = ast.unparse(ast.Module(body=rename_module, type_ignores=[])) if rename_module else ''

    # Step 4: Apply name_map to VM source so function/global references match.
    #         exec_source is already correctly named (from Step 1's rename).
    #         Do NOT apply name_map to exec_source — funcenc adds new code
    #         (e.g. _xor_stream's loop vars a,b) that would be corrupted.
    if name_map:
        vm_source = apply_rename(vm_source, name_map, attr_map)

    if rename_imports:
        sys.stderr.write(f'[split] moved {len(rename_imports)} import(s) to exec part\n')
    sys.stderr.write(f'[split] name_map={name_map}\n')

    return exec_source, vm_source

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write('usage: python3 vm_split.py <obf_script_path> [techniques]\n')
        sys.exit(1)
    obf_path = sys.argv[1]
    techniques = sys.argv[2].strip() if len(sys.argv) > 2 else ''
    source = sys.stdin.read()
    if not source:
        sys.stderr.write('error: no input\n')
        sys.exit(1)
    exec_src, vm_src = pipeline(source, obf_path, techniques)
    sys.stdout.write('#===EXEC_SOURCE===\n')
    sys.stdout.write(exec_src)
    sys.stdout.write('\n#===VM_SOURCE===\n')
    sys.stdout.write(vm_src)
    sys.stdout.write('\n')
)vm_split";
#endif
