import argparse
import json
import sys
import angr

from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor

target_func_prototype_field = 'funcPrototype'
func_addr_field = 'funcAddr'
func_name_field = 'funcName'
var_names_field = 'varNames'
var_ctypes_field = 'varCTypes'
ret_type_field = 'retType'
short_circuit_func_prototypes_field = "shortCircuitFuncPrototypes"

def main():
    parser = argparse.ArgumentParser(description='The driver script to be used by Ghidra. This is not te be run manually.')
    parser.add_argument('elf', help='The path to the binary to analyze')
    parser.add_argument('input_json', help='The JSON encoded input to the script')

    args = parser.parse_args()
    bin_file_path = args.elf
    input_args_json = args.input_json

    input_args = json.loads(input_args_json)

    if target_func_prototype_field not in input_args:
        print("We need the prototype of the target function", file=sys.stderr)
        return -1

    target_func_prototype = input_args[target_func_prototype_field]

    if func_addr_field not in target_func_prototype:
        print("We need the address of the function to analyze", file=sys.stderr)
        return -1
    target_func_addr = target_func_prototype[func_addr_field] + 0x300000


    if func_name_field not in target_func_prototype:
        print("We need the name of the function to analyze", file=sys.stderr)
        return -1
    target_func_name = target_func_prototype[func_name_field]

    if var_names_field not in target_func_prototype:
        print("We need the names of the symbolic variables to use for analysis", file=sys.stderr)
        return -1
    var_names = target_func_prototype[var_names_field]

    if var_ctypes_field not in target_func_prototype:
        print("We need the types of the symbolic variables to use for analysis", file=sys.stderr)
        return -1
    var_ctypes = target_func_prototype[var_ctypes_field]

    if ret_type_field not in target_func_prototype:
        print("We need the return type of the function to use for analysis", file=sys.stderr)
        return -1
    ret_type = target_func_prototype[ret_type_field]

    if short_circuit_func_prototypes_field not in input_args:
        print("We need function prototypes of the functions we need to short circuit.")
        return -1

    short_circuit_func_prototypes = input_args[short_circuit_func_prototypes_field]
    short_circuit_calls = {}
    for short_circuit_func_prototype in short_circuit_func_prototypes:
        sc_func_addr = short_circuit_func_prototype[func_addr_field] + 0x300000
        sc_func_name = short_circuit_func_prototype[func_name_field]
        sc_var_ctypes = short_circuit_func_prototype[var_ctypes_field]
        sc_ret_ctype = short_circuit_func_prototype[ret_type_field]

        short_circuit_calls[sc_func_addr] = (sc_func_name, sc_var_ctypes, sc_ret_ctype)

    print("Creating proj...", file=sys.stderr)
    proj = angr.Project(bin_file_path, auto_load_libs=False)
    print("Creating CFG...", file=sys.stderr)
    cfg = proj.analyses.CFGFast(normalize=True)
    target_func = cfg.functions.function(name=target_func_name)
    if target_func is None:
        target_func = cfg.functions.function(addr=target_func_addr)
        if target_func is None:
            raise Exception("Cannot find function: {}@{}".format(target_func_name, target_func_addr))
        target_func_name = target_func.name
    print("Target func: {}@0x{:x}".format(target_func.name, target_func.addr), file=sys.stderr)

    see  = SymbolicExpressionExtractor(bin_file_path, proj=proj, cfg=cfg)
    extracted_symexpr = see.extract(target_func_name, var_names, var_ctypes, ret_type, False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    print("done extracting", file=sys.stderr)
    print("Symbolic Expression Extracted: {}".format(len(ast)), file=sys.stderr)
    #print(ast)
    print("".join(extracted_symexpr.symex_to_infix()))


    return 0


if __name__ == "__main__":
    sys.exit(main())
