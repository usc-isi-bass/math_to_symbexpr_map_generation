import angr
import claripy
from angr.sim_options import LAZY_SOLVES,\
    SIMPLIFY_EXPRS,\
    SIMPLIFY_MEMORY_READS,\
    SIMPLIFY_MEMORY_WRITES,\
    SIMPLIFY_REGISTER_READS,\
    SIMPLIFY_REGISTER_WRITES,\
    SIMPLIFY_RETS,\
    SIMPLIFY_EXIT_STATE,\
    SIMPLIFY_EXIT_TARGET,\
    SIMPLIFY_EXIT_GUARD,\
    SIMPLIFY_CONSTRAINTS
import claripy
import re
from collections.abc import Iterable
from collections import deque


from expression.components import *
from code_generation.c_code_generation import GeneratedCCode

simplification_options = [
    SIMPLIFY_EXPRS,
    SIMPLIFY_MEMORY_READS,
    SIMPLIFY_MEMORY_WRITES,
    SIMPLIFY_REGISTER_READS,
    SIMPLIFY_REGISTER_WRITES,
    SIMPLIFY_RETS,
    SIMPLIFY_EXIT_STATE,
    SIMPLIFY_EXIT_TARGET,
    SIMPLIFY_EXIT_GUARD,
    SIMPLIFY_CONSTRAINTS
]

SYM_BINOPS = [op for (_, op, _) in BINARY_OPERATORS] + \
        [op for (_, op, _) in BINARY_BIT_OPERATORS] + \
        ["Concat", "Extract"]
SYM_UNFUNCS = [op for (_, op, _) in UNARY_FUNCTIONS]
SYM_BINFUNCS = [op for (_, op, _) in BINARY_FUNCTIONS]
SYM_UNFUNCS_d = {func:op for (func, op, _) in UNARY_FUNCTIONS}
SYM_BINFUNCS_d = {func:op for (func, op, _) in BINARY_FUNCTIONS}


def sym_prefix_to_infix(prefix):
    stack = []

    # read prefix in reverse order
    i = len(prefix) - 1
    while i >= 0:
        if not (prefix[i] in SYM_BINOPS or \
                prefix[i] in SYM_BINFUNCS or \
                prefix[i] in SYM_UNFUNCS):
            # symbol is operand
            if prefix[i] == "Concat":
                stack.append("..")
            else:
                stack.append(prefix[i])
            i -= 1
        else:
            # symbol is operator
            if prefix[i] in SYM_UNFUNCS:
                # Unary operators
                op1 = stack.pop()
                if not isinstance(op1, list):
                    op1 = [op1]
                sym = [prefix[i]] + ["("] + op1 + [")"]
                stack.append(sym)
            elif prefix[i] in SYM_BINFUNCS:
                # Unary operators
                op1 = stack.pop()
                if not isinstance(op1, list):
                    op1 = [op1]
                op2 = stack.pop()
                if not isinstance(op2, list):
                    op2 = [op2]
                sym = [prefix[i]] + ["("] + op1 + [","] + op2 + [")"]
                stack.append(sym)
            else:
                op1 = stack.pop()
                if not isinstance(op1, list):
                    op1 = [op1]
                op2 = stack.pop()
                if not isinstance(op2, list):
                    op2 = [op2]
                sym = ["("] + op1 + [prefix[i]] + op2 + [")"]
                stack.append(sym)
            i -= 1

    return stack.pop()

def _s32(value):
    return -(value & 0x80000000) | (value & 0x7fffffff)

def _process_token(token):
    # May get xxx[31:0] for unsimplified expressions
    # Discard this first
    token = re.sub(r"\[\d{1,2}:\d{1,2}\]", "", token)

    # First handle hex numbers
    if token == "0x0":
        # Probably padding 0, keep it
        return token

    elif re.fullmatch(r"0xff+[0-9A-Fa-f]+", token):
        # 0xfff*, probably negative number, transfer to decimal
        number = _s32(int(token, 16))
        return str(number)

    elif re.fullmatch(r"0x[0-9A-Fa-f]{2}f{6}", token):
        # FIXME
        # 0x*ffffff, probably -1 after shifting
        return "-1"

    elif re.fullmatch(r"0x[0-9A-Fa-f]{1,8}", token):
        return str(int(token, 16))

    elif token == "__add__" or token == "fpAdd":
        return "+"

    elif token == "__sub__" or token == "fpSub":
        return "-"

    elif token == "__mul__" or token == "fpMul":
        return "*"

    elif token == "__div__" or token == "SDiv" or token == "fpDiv":
        return "/"

    elif token == "__mod__" or token == "SMod":
        return "%"
    
    elif token == "__lshift__":
        return "<<"
    
    elif token == "__rshift__":
        return ">>"
    
    elif token == "__xor__":
        return "^"

    else:
        return token

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
        self.setup_func_simprocs()



    def extract(self, target_func_name: str, symvar_names: Iterable, symvar_ctypes: Iterable, ret_type: str, simplified=True):
        '''
        Extract the AST of the return value of a target function.
            target_func_name: The name of the function to perform symbolic execution on.
            symvar_names:     The names of the symbolic variables to pass this function as parameters.
            symvar_types:     The types of the symbolic variables to pass this function as parameters.
            ret_type:         The type of the return value of this function
            simplified:       To simplify the symbolic expression or not
        '''
        target_func = self.cfg.functions.function(name=target_func_name)
        assert target_func is not None, "Could not find a function by name: {}".format(target_func_name)
        func_addr = target_func.addr

        # Create BVS for integer/long arguments, and FPS for float/double
        num_symvars = len(symvar_names)
        func_symvar_args = []
        is_fp_args = []
        for i in range(num_symvars):
            ctype = symvar_ctypes[i]
            name = symvar_names[i]
            if ctype in C_TYPES_INT:
                func_symvar_args.append(claripy.BVS(name, 64, explicit_name=True))
                is_fp_args.append(False)
            else:
                func_symvar_args.append(claripy.FPS(name, claripy.fp.FSORT_DOUBLE, explicit_name=True))
                is_fp_args.append(True)

        if ret_type in C_TYPES_INT:
            ret_fp = False
        else:
            ret_fp = True

        # Create a new symbolic calling convention based on the original target function
        # With correct types of arguments and return type
        sym_cc = self.proj.factory.cc_from_arg_kinds(fp_args=is_fp_args, ret_fp=ret_fp)

        if simplified:
            start_state = self.proj.factory.call_state(func_addr, *func_symvar_args, cc=sym_cc)
        else:
            start_state = self.proj.factory.call_state(func_addr, *func_symvar_args, cc=sym_cc, add_options=[LAZY_SOLVES], remove_options=simplification_options)

        simgr = self.proj.factory.simulation_manager(start_state)
        simgr.run()

        ret_reg_name = sym_cc.return_val.reg_name

        if len(simgr.deadended) > 1:
            symex_expr = claripy.Or(*list(state.regs.get(ret_reg_name) for state in simgr.deadended))
        elif len(simgr.deadended) == 1:
            state = simgr.deadended[0]
            symex_expr = state.regs.get(ret_reg_name)
        else:
            raise Exception("No deadended states in simulation manager: {}".format(simgr.stashes))

        return ExtractedSymExpr(symex_expr, func_symvar_args)

    def setup_func_simprocs(self):
        double_length = claripy.fp.FSORT_DOUBLE.length
        class UnaFuncSymProc(angr.SimProcedure):
            def run(self, x, op=None):
                x_claripy = x.to_claripy()
                if x_claripy.length > double_length:
                    x_claripy = x_claripy[double_length-1:0]
                x_fp = x_claripy.raw_to_fp()
                return op(x_fp)
        una_cc = self.proj.factory.cc_from_arg_kinds((True,), ret_fp=True)
        for func_name, symbol_name, (arg, ret) in UNARY_FUNCTIONS:
            una_func_op = claripy.operations.op(func_name, (claripy.ast.fp.FP,), claripy.ast.fp.FP, do_coerce=False, calc_length=lambda x: double_length)
            self.proj.hook_symbol(symbol_name, UnaFuncSymProc(cc=una_cc, op=una_func_op))
        class BinFuncSymProc(angr.SimProcedure):
            def run(self, x, y, op=None):
                x_claripy = x.to_claripy()
                y_claripy = y.to_claripy()
                if x_claripy.length > double_length:
                    x_claripy = x_claripy[double_length-1:0]
                x_fp = x_claripy.raw_to_fp()
                if y_claripy.length > double_length:
                    y_claripy = y_claripy[double_length-1:0]

                y_fp = y_claripy.raw_to_fp()
                return op(x_fp, y_fp)
        bin_cc = self.proj.factory.cc_from_arg_kinds((True,True), ret_fp=True)
        for func_name, symbol_name, (arg, ret) in BINARY_FUNCTIONS:
            bin_func_op = claripy.operations.op(func_name, (claripy.ast.fp.FP,claripy.ast.fp.FP), claripy.ast.fp.FP, do_coerce=False, calc_length=lambda x, y: double_length)
            self.proj.hook_symbol(symbol_name, BinFuncSymProc(cc=bin_cc, op=bin_func_op))




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
            seq.append(_process_token(token))
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
        return [var]


    def _symex_to_prefix(self, expr, use_heuristics=True):
        if not hasattr(expr, "op"):
            return [str(expr)]
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
            if use_heuristics:
                # Merge SignExt (a[31:0] >> 0x1f .. a[31:0])
                if hasattr(expr.args[0], "op") and str(expr.args[0].op) == "__rshift__":
                    child1 = expr.args[0].args[0]
                    child2 = expr.args[1]
                    if (child1 == child2).is_true():
                        return self._symex_to_prefix(child1)

                # Merge ZeroExt
                if hasattr(expr.args[0], "op") and str(expr.args[0].op) == "BVV":
                    if str(hex(expr.args[0].args[0])) == "0x0":
                        return self._symex_to_prefix(expr.args[1])

                # For case <BV128 (0x0 .. fpToIEEEBV()[127:32] .. fpToIEEEBV())>
                # Only return the first fpToIEEEBV()
                if len(expr.args) == 2 and \
                   hasattr(expr.args[0], "op") and str(expr.args[0].op) == "Extract" and \
                   expr.args[0].args[0] == 127 and expr.args[0].args[1] == 32 and \
                   hasattr(expr.args[1], "op") and expr.args[1].op == "fpToIEEEBV":
                    return self._symex_to_prefix(expr.args[0].args[2])


        elif op == "Extract":
            if not use_heuristics:
                return [op, str((expr.args[0], expr.args[1]))] + self._symex_to_prefix(expr.args[2])
            else:
                # Discard "Extract" expression
                return self._symex_to_prefix(expr.args[2])

        elif (op == "ZeroExt" or op == "SignExt") and use_heuristics:
            return self._symex_to_prefix(expr.args[1])

        elif op == "fpToIEEEBV" or op == "FPS" or op == "FPV":
            return self._symex_to_prefix(expr.args[0])

        elif op == "fpToFP":
            if isinstance(expr.args[0], claripy.fp.RM):
                return self._symex_to_prefix(expr.args[1])
            else:
                return self._symex_to_prefix(expr.args[0])

        elif op == "BVS":
            # FIXME:
            # if <use_heuristic>, we extracted variable at "Extract", won't execute here
            return [str(expr.args[0])]

        elif op == "fpAdd" or \
                op == "fpSub" or \
                op == "fpMul" or \
                op == "fpDiv":
            return [op] + self._symex_to_prefix(expr.args[1]) + self._symex_to_prefix(expr.args[2])
        
        elif op == "fpNeg":
            return ["*", "-1"] + self._symex_to_prefix(expr.args[0])

        elif op in SYM_UNFUNCS_d:
            return [SYM_UNFUNCS_d[op]] + self._symex_to_prefix(expr.args[0])

        elif op in SYM_BINFUNCS_d:
            return [SYM_BINFUNCS_d[op]] + self._symex_to_prefix(expr.args[0]) + self._symex_to_prefix(expr.args[1])

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


    def symex_to_prefix(self, use_heuristics=True):
        symex_expr = self.symex_expr
        prefix = self._symex_to_prefix(symex_expr)

        if use_heuristics and \
           len(prefix) > 2 and \
           prefix[0] == "Concat" and \
           prefix[1].startswith("reg_"):
            prefix = prefix[2:]

        return [_process_token(elem) for elem in prefix]



