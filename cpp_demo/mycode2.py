import angr
import claripy
import pyvex
import networkx

proj = angr.Project("manual", load_options={'auto_load_libs': False})
sy = proj.loader.find_symbol("simple")

cfg = proj.analyses.CFGFast()
func_addr = sy.rebased_addr

func_symvar_args = []
func_symvar_args.append(claripy.BVS("q1", 64, explicit_name=True))
func_symvar_args.append(claripy.BVS("q2", 64, explicit_name=True))
func_symvar_args.append(claripy.BVS("output*", 64, explicit_name=True))
is_fp_args = [False, False, False]
ret_fp = False

sym_cc = proj.factory.cc_from_arg_kinds(fp_args=is_fp_args, ret_fp=ret_fp)
start_state = proj.factory.call_state(func_addr, *func_symvar_args, cc=sym_cc)


