import idaapi
import idc
import idautils
import ida_name
import json
import sys
from dataclasses import dataclass

SYMCOL_OPERATOR_NEW = [
    '??2@YAPEAX_KAEBUnothrow_t@std@@@Z',    # operator new(uint64, std::nothrow_t)
    '??2@YAPEAX_K@Z'                        # operator new(uint64)
]

# constructor
SYMPFX_CONSTRUCTOR = '??0'

# TODO: itanium support
# TODO: array & user-defined & aligned

@dataclass
class AnalyzeResult:
    ctor: str | None
    allocated: int
    vars: list[str]

RAWDATA: list[AnalyzeResult] = list()

class MemoryAllocationVisitor(idaapi.ctree_visitor_t):
    def __init__(self, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)

    def ignore_cast(self, obj):
        if obj.op == idaapi.cot_cast: # ignore cast
            return obj.x
        return obj

    def handle_potential_ctor(self, expr):
        func_name = idaapi.get_func_name(expr.x.obj_ea)
        if func_name and func_name.startswith(SYMPFX_CONSTRUCTOR):
            if expr.a.size() < 1:
                print('unreasonable function call at: ' + func_name)
                return
            arg = self.ignore_cast(expr.a[0]) # get first arg
            if arg.op != idaapi.cot_var:
                return 0 # unsupported
            arg_var_name = arg.v.getv().name
            for obj in RAWDATA:
                if arg_var_name in obj.vars:
                    obj.ctor = func_name
                    obj.vars.clear() # prevent getting messed up by the optimizer

    def visit_expr(self, expr) -> int:
        if expr.op == idaapi.cot_asg:
            first = expr.x
            last = self.ignore_cast(expr.y)
            # print(f'found expr: {first.opname}, {last.opname}')
            if first.op == idaapi.cot_var:
                var_name = first.v.getv().name
                # print(var_name)
                if last.op == idaapi.cot_call:
                    func_name = idaapi.get_func_name(last.x.obj_ea)
                    if func_name in SYMCOL_OPERATOR_NEW:
                        arg = self.ignore_cast(last.a[0]) # get first arg
                        if arg.op != idaapi.cot_num:
                            return 0 # unsupported
                        allocated = arg.numval()
                        RAWDATA.append(AnalyzeResult(None, allocated, [ var_name ]))
                        # print(f'    allocated: {allocated}')
                        return 0
                    self.handle_potential_ctor(last)
                if last.op == idaapi.cot_var: # var = var
                    last_var_name = last.v.getv().name
                    for obj in RAWDATA:
                        # why should we consider performance in python?
                        if var_name in obj.vars and last_var_name not in obj.vars:
                            obj.vars.append(last_var_name)
                        if last_var_name in obj.vars and var_name not in obj.vars:
                            obj.vars.append(var_name)
        elif expr.op == idaapi.cot_call:
            self.handle_potential_ctor(expr)
        return 0

def remove_access_descriptor(demangled: str) -> str: # 'public: '...
    return demangled[demangled.find(' ') + 1:]

def remove_parameter_list(demangled: str) -> str: # 'a::b<void()>::c(p1,p2)'...
    stack = []
    final_L = 0
    idx = 0
    while idx < len(demangled):
        match demangled[idx]:
            case '(':
                stack.append(idx)
            case ')':
                final_L = stack.pop()
        idx += 1
    return demangled[:final_L]

def remove_function_call(demangled: str) -> str: # 'a<void()>::b<int>'...
    demangled = remove_access_descriptor(demangled)
    demangled = remove_parameter_list(demangled)
    idx = len(demangled)
    should_ignore_brackets = 0
    while idx >= 0:
        idx -= 1
        # print(char)
        match demangled[idx]:
            case '<' | '(':
                should_ignore_brackets -= 1
            case '>' | ')':
                should_ignore_brackets += 1
            case ':':
                if should_ignore_brackets > 0:
                    continue
                assert(demangled[idx - 1] == ':') # next char
                return demangled[:idx - 1]
    print(demangled)
    assert(False) # unreachable

def class_name_by_mangled(symbol: str) -> str | None:
    result = ida_name.demangle_name(symbol, 0)
    if not result:
        return None
    return remove_function_call(result)

def main():

    related_xrefs = set()
    for new_sym in SYMCOL_OPERATOR_NEW:
        ea = idc.get_name_ea_simple(new_sym)
        if ea == idc.BADADDR:
            print('can\'t get address for ' + new_sym)
        else:
            for xref in idautils.XrefsTo(ea):
                related_xrefs.add(xref.frm)
    
    all_count = len(related_xrefs)
    current_count = 0
    result = dict()
    for xref in related_xrefs:
        current_count += 1
        print(f'({current_count}/{all_count})-> {idaapi.get_func_name(xref)}')
        cfunc = idaapi.decompile(xref)
        if not cfunc:
            print('could not decompile: ' + hex(xref))
            continue
        RAWDATA.clear()
        MemoryAllocationVisitor(cfunc).apply_to(cfunc.body, None)
        for obj in RAWDATA:
            if not obj.ctor:
                continue
            class_name = class_name_by_mangled(obj.ctor)
            if not class_name:
                print(f'    failed to demangle: {obj.ctor}')
                continue
            if class_name not in result:
                result[class_name] = obj.allocated
                print(f'    added {class_name} ({hex(obj.allocated)})')
            elif result[class_name] > obj.allocated:
                # print(f'    warning, inconsistent result: {class_name} ({hex(result[class_name])} != {hex(obj.allocated)})')
                print(f'assuming Hex-Rays is always correct, we take the minimum value ({result[class_name]} => {obj.allocated})')
                result[class_name] = obj.allocated
    
    with open('dump.json', 'w') as file:
        file.write(json.dumps(result))

if __name__ == '__main__':
    main()