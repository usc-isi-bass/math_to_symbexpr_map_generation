import angr
import claripy
import pyvex
import networkx

proj = angr.Project("AP_SteerController.o", load_options={'auto_load_libs': False})
cfg = proj.analyses.CFGFast()

sy = proj.loader.find_symbol("_ZN18AP_SteerController21get_steering_out_rateEf")
func_addr = sy.rebased_addr

func_symvar_args = []
func_symvar_args.append(claripy.FPS("desired_rate", claripy.fp.FSORT_DOUBLE, explicit_name=True))
is_fp_args = [True]
ret_fp = False

sym_cc = proj.factory.cc_from_arg_kinds(fp_args=is_fp_args, ret_fp=ret_fp)
start_state = proj.factory.call_state(func_addr, *func_symvar_args, cc=sym_cc)


