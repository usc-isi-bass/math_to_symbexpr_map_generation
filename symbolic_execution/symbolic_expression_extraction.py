import angr
import claripy
import re
from collections.abc import Iterable
from collections import deque


from code_generation.c_code_generation import GeneratedCCode

def s32(value):
    return -(value & 0x80000000) | (value & 0x7fffffff)

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

    def symex_to_seq(self):
        symex_expr = str(self.symex_expr).replace("(", "( ").replace(")", " )")
        expr = symex_expr.replace("<BV64 ", "")[:-1]
        tokens = expr.split()
        seq = []

        for token in tokens:
            # First handle hex numbers
            if token == "0x0":
                # Probably padding 0, keep it
                seq.append(token)

            elif re.match(r"0xf\w{7}", token):
                # 0xfff*, probably negative number, transfer to decimal
                number = s32(int(token, 16))
                seq.append(str(number))

            elif re.match(r"0x\w{2}f{6}", token):
                # FIXME
                # 0x*ffffff, probably -1 after shifting
                seq.append("-1")

            elif re.match(r"0x\w{1,8}", token):
                seq.append(str(int(token, 16)))

            # Variable bit extraction
            elif re.match(r"\w+\[\d{1,2}:\d{1,2}\]", token):
                seq.append(token.split("[")[0])

            else:
                seq.append(token)
        return seq

    def _try_merge_same_variable_concat(self, args):
        # Try to match the form
        # (a[7:0] .. a[15:8] .. a[23:16] .. a[31:24])

        # Check if all args are 'BVV'
        for arg in args:
            if not isinstance(arg, claripy.ast.bv.BV) \
               or str(arg.op) != "Extract":
                return None

        # Check if they are extracting from the same variable
        var = args[0].args[2].args[0]
        for arg in args:
            if arg.args[2].args[0] != var:
                return None

        # Check if the extracting bit indexes are in sequence
        arg = args.pop(0)
        idx = arg.args[0]
        start = arg.args[1]
        while len(args) > 0:
            arg = args.pop(0)
            if arg.args[1] != idx + 1:
                return None
            idx = arg.args[0]
        # Discard "Extract" expression
        #return ["Extract", "(%s, %s)" % (idx, start), var]
        return [var]


    def _symex_to_prefix(self, expr):
        op = str(expr.op)

        if op == "BVV":
            # Constant value
            return [str(hex(expr.args[0]))]

        elif op == "Concat":
            # Handle special case of
            # (a[7:0] .. a[15:8] .. a[23:16] .. a[31:24])
            # If not this case, do nothing here
            queue = self._try_merge_same_variable_concat(list(expr.args))
            if queue is not None:
                return queue

        elif op == "Extract":
            # Variable Extraction
            # Discard "Extract" expression
            #return [op, str((expr.args[0], expr.args[1])), expr.args[2].args[0]]
            return [expr.args[2].args[0]]

        elif op == "BVS":
            # FIXME:
            # if we extracted variable at "Extract", won't execute here
            return [str(expr.args[0])]

        children = []
        ast_queue = deque([iter(expr.args)])
        while ast_queue:
            try: 
                ast = next(ast_queue[-1])
            except StopIteration:
                ast_queue.pop()
                continue
            children.append(self._symex_to_prefix(ast))

        # Claripy will merge same operations into one ast
        # e.g. (a + b + c) will be one ast, "+" with 3 args
        if len(expr.args) == 2:
            return [op] + children[0] + children[1]
        else:
            prefix_queue = []
            while len(children) > 1:
                prefix_queue += [op]
                prefix_queue += children.pop(0)
            prefix_queue += children.pop(0)
            return prefix_queue



    def symex_to_prefix(self):
        symex_expr = self.symex_expr
        return self._symex_to_prefix(symex_expr)


