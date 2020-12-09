import angr
import claripy
from collections.abc import Iterable

from code_generation.c_code_generation import GeneratedCCode

#######################################
#
# Perform symbolic execution on functions in a binary executable and extract the AST of the return value.
#
#######################################

class SymbolicExpressionExtractor:

    #######################################
    #
    # SymbolicExpressionExtractor(elf_file_name)
    #    +-     elf_file_name: The name of the binary file to analyze.
    #
    #######################################

    def __init__(self, elf_file_name):
        self.elf_file_name = elf_file_name
        self.proj = angr.Project(elf_file_name, auto_load_libs=False)
        self.cfg = self.proj.analyses.CFGFast(normalize=True)
        self.proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=self.cfg.model, analyze_callsites=True)



    def extract(self, target_func_name: str, symvar_names: Iterable):
        '''
        Extract the AST of the return value of a target function.
            target_func_name: The name of the function to perform symbolic execution on.
            symvar_names:     The names of the symbolic variables to pass this function as parameters.
        '''
        target_func = self.cfg.functions.function(name=target_func_name)
        assert target_func is not None, "Could not find a function by name: {}".format(target_func_name)
        func_addr = target_func.addr

        num_symvars = len(symvar_names)
        func_args = target_func.calling_convention.args
        num_params_cc = len(func_args)

        if num_params_cc != num_symvars:
            raise Exception("Function calling convention indicates {} args required, but {} supplied.".format(num_params_cc, num_symvars))
        func_symvar_args = [claripy.BVS(symvar_name, size=arg.size * 8, explicit_name=True) for symvar_name, arg in zip(symvar_names, func_args)]
        #start_state = self.proj.factory.call_state(func_addr, *func_symvar_args, add_options=[angr.sim_options.LAZY_SOLVES])
        start_state = self.proj.factory.call_state(func_addr, *func_symvar_args)

        simgr = self.proj.factory.simulation_manager(start_state)
        simgr.run()

        ret_reg_name = target_func.calling_convention.return_val.reg_name

        if len(simgr.deadended) > 1:
            symex_expr = claripy.Or(*list(state.regs.get(ret_reg_name) for state in simgr.deadended))
        elif len(simgr.deadended) == 1:
            state = simgr.deadended[0]
            symex_expr = state.regs.get(ret_reg_name)
        else:
            raise Exception("No deadended states in simulation manager: {}".format(simgr.stashes))

        return ExtractedSymExpr(symex_expr, func_symvar_args)


        
class ExtractedSymExpr:
    #######################################
    #
    # ExtractedSymExpr(symex_expr, symvars)
    #    An object to house the extracted symbolic expression and supplied input variables.
    #    +-     symex_expr: The symbolic expression.
    #    +-     symvars:    The supplied symbolic variables.
    #
    #######################################

    def __init__(self, symex_expr, symvars):
        self.symex_expr = symex_expr
        self.symvars = symvars
