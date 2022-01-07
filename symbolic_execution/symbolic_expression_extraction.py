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
import logging
log = logging.getLogger('symbolic_expression_extraction')


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
        ["..", ">", ">=", "<=", "<", "==", "!=", "&&", "||"]
SYM_UNFUNCS = [op for (_, op, _) in UNARY_FUNCTIONS]
SYM_BINFUNCS = [op for (_, op, _) in BINARY_FUNCTIONS]
SYM_UNFUNCS_d = {func:op for (func, op, _) in UNARY_FUNCTIONS}
SYM_BINFUNCS_d = {func:op for (func, op, _) in BINARY_FUNCTIONS}


def sym_prefix_to_infix(prefix):
    log.warning("Legacy: Only infix is used now")
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
    if re.fullmatch(r"0xff+[0-9A-Fa-f]+", token):
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

    elif token == "And" or token == "__and__":
        return "&&"

    elif token == "Or" or token == "__or__":
        return "||"

    elif token == "SLT" or token == "ULT" or token == "fpLT":
        return "<"

    elif token == "SLE" or token == "ULE" or token == "fpLE":
        return "<="

    elif token == "SGE" or token == "UGE" or token == "fpGE":
        return ">="

    elif token == "SGT" or token == "UGT" or token == "fpGT":
        return ">"

    elif token == "__eq__" or token == "fpEQ":
        return "=="

    elif token == "__ne__" or token == "fpNE":
        return "!="

    elif token == "__lshift__":
        return "<<"

    elif token == "__rshift__":
        return ">>"

    elif token == "__xor__":
        return "^"

    elif token == "Concat":
        return ".."

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

    def __init__(self, elf_file_name, proj=None, cfg=None):
        self.elf_file_name = elf_file_name
        self.proj = proj
        if self.proj is None:
            self.proj = angr.Project(elf_file_name, auto_load_libs=False)
        self.cfg = cfg
        if self.cfg is None:
            self.cfg = self.proj.analyses.CFGFast(normalize=True)
        self.setup_func_simprocs()


    def extract(self, target_func_name: str, symvar_names: Iterable, symvar_ctypes: Iterable, ret_type: str, simplified=True, short_circuit_calls={}):
        '''
        Extract the AST of the return value of a target function.
            target_func_name:       The name of the function to perform symbolic execution on.
            symvar_names:           The names of the symbolic variables to pass this function as parameters.
            symvar_types:           The types of the symbolic variables to pass this function as parameters.
            ret_type:               The type of the return value of this function
            simplified:             To simplify the symbolic expression or not
            short_circuit_calls:    A map from the addresses of the functions we want to skip, to a tuple (func_name, (arg1_type, arg2_type, ...), ret_type).
        '''
        target_func = self.cfg.functions.function(name=target_func_name)
        assert target_func is not None, "Could not find a function by name: {}".format(target_func_name)
        func_addr = target_func.addr

        self._hook_func_callsites(short_circuit_calls)

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
            #start_state = self.proj.factory.call_state(func_addr, *func_symvar_args, cc=sym_cc, add_options=[LAZY_SOLVES], remove_options=simplification_options)
            start_state = self.proj.factory.call_state(func_addr, *func_symvar_args, cc=sym_cc, remove_options=simplification_options)


        sym_addr_writes = {}
        sym_addr_rd_to_addr = {}
        def mem_rd_bp(state):
            addr = state.inspect.mem_read_address
            #expr = state.inspect.mem_read_expr
            leng = state.inspect.mem_read_length
            expr = state.memory.load(addr, size=leng, disable_actions=True, inspect=False) # XXX For some reason I think expr is sometimes wrong
            #print("READ: expr: {} data: {}".format(expr, data))
            cond = state.inspect.mem_read_condition
            #load_op = claripy.operations.op("LD", (claripy.ast.bv.BV,), claripy.ast.bv.BV, do_coerce=True, calc_length=lambda x: leng * 8)
            #print("READ: insn: {} addr: {} expr: {} len: {} cond: {}".format(state.regs.ip, addr, expr, leng, cond))
            uninit = expr is None or (expr.uninitialized )
            #print("^READ: uninit: {}".format(uninit))
            
            if uninit is True:
                #load_op_addr = load_op(addr)
                addr_bvs = claripy.BVS('a', size=addr.size(), explicit_name=False)
                sym_addr_rd_to_addr[addr_bvs] = addr
                #print(addr)
                #print("^READ: storing {} at {}".format(load_op_addr, addr))
                #state.memory.store(addr, load_op_addr, disable_actions=True, inspect=False)
                state.memory.store(addr, addr_bvs, disable_actions=True, inspect=False)
                #state.inspect.mem_read_expr = load_op(expr)

        def mem_wr_bp(state):
            addr = state.inspect.mem_write_address
            expr = state.inspect.mem_write_expr
            leng = state.inspect.mem_write_length
            cond = state.inspect.mem_write_condition
            if addr.symbolic:
                sym_addr_writes[addr] = expr
            #print("WRITE: insn: {} addr: {} expr: {} len: {} cond: {}".format(state.regs.ip, addr, expr, leng, cond))
            
        start_state.inspect.b('mem_read', when=angr.BP_BEFORE, action=mem_rd_bp)
        start_state.inspect.b('mem_write', when=angr.BP_BEFORE, action=mem_wr_bp)

        simgr = self.proj.factory.simulation_manager(start_state)
        #simgr.run()
        while len(simgr.active) > 0:
            for state in simgr.active:
                print("0x{:x}".format(state.addr, end=' '))
            simgr.step()
        ret_reg_name = sym_cc.return_val.reg_name
        print("")

        if len(simgr.deadended) > 1:
            states = simgr.deadended
            state,_ , merge_occurred = states[0].merge(*states[1:], merge_conditions=[*[state.history.jump_guards for state in states]])
            if not merge_occurred:
                raise Exception("Merge state failed!")
        elif len(simgr.deadended) == 1:
            state = simgr.deadended[0]
        else:
            raise Exception("No deadended states in simulation manager: stashes: {} errored: {}".format(simgr.stashes, simgr.errored))
        #print("RDI: {}".format(state.regs.rdi))
        #print("[RDI]: {}".format(state.memory.load(state.regs.rdi, size=4, disable_actions=True, inspect=False)))
        #print("[RDI+4]: {}".format(state.memory.load(state.regs.rdi+4, size=4, disable_actions=True, inspect=False)))
            

        print("Symbolic writes:")
        for sym_addr, expr in sym_addr_writes.items():
            for sym_addr_rd, addr in sym_addr_rd_to_addr.items():
                load_op = claripy.operations.op("LD", (claripy.ast.bv.BV,), claripy.ast.bv.BV, do_coerce=True, calc_length=lambda x: sym_addr_rd.size())
                expr = expr.replace(sym_addr_rd, load_op(addr))
            print("    {}: {}".format(sym_addr, expr))
        symex_expr = state.regs.get(ret_reg_name)
        for sym_addr_rd, addr in sym_addr_rd_to_addr.items():
            load_op = claripy.operations.op("LD", (claripy.ast.bv.BV,), claripy.ast.bv.BV, do_coerce=True, calc_length=lambda x: sym_addr_rd.size())
            symex_expr = symex_expr.replace(sym_addr_rd, load_op(addr))
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
            func = self.cfg.functions.function(name=symbol_name)
            if func is not None:
                una_func_op = claripy.operations.op(func_name, (claripy.ast.fp.FP,), claripy.ast.fp.FP, do_coerce=False, calc_length=lambda x: double_length)
                self.proj.hook_symbol(func.addr, UnaFuncSymProc(cc=una_cc, op=una_func_op))
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
            func = self.cfg.functions.function(name=symbol_name)
            if func is not None:
                bin_func_op = claripy.operations.op(func_name, (claripy.ast.fp.FP,claripy.ast.fp.FP), claripy.ast.fp.FP, do_coerce=False, calc_length=lambda x, y: double_length)
                self.proj.hook_symbol(func.addr, BinFuncSymProc(cc=bin_cc, op=bin_func_op))


    def _hook_func_callsites(self, short_circuit_calls):
        double_length = claripy.fp.FSORT_DOUBLE.length

        for call_insn_addr, func_types in short_circuit_calls.items():
            if not self.proj.is_hooked(call_insn_addr):
                func_name = func_types[0]
                cfg_node = self.cfg.model.get_any_node(addr=call_insn_addr, anyaddr=True)
                if cfg_node is None:
                    raise Exception("Could not find a CFGNode for addr: 0x{:x}".format(call_insn_addr))
                func = self.cfg.functions.function(addr=cfg_node.function_address)
                assert func is not None
                if func_name is None:
                    call_target = func.get_call_target(cfg_node.addr)
                    if call_target is None:
                        func_name = "indirect"
                    else:
                        tgt_func = self.cfg.functions.function(addr=call_target)
                        if tgt_func.is_simprocedure and tgt_func.name == 'UnresolvableCallTarget':
                            func_name = 'indirect'
                        else:
                            func_name = tgt_func.name

                func_arg_types = func_types[1]
                func_ret_type = func_types[2]

                func_op_arg_types = [claripy.ast.fp.FP if (arg_type in C_TYPES_FLOAT) else claripy.ast.bv.BV for arg_type in func_arg_types]
                func_op_ret_type = claripy.ast.fp.FP if (func_ret_type in C_TYPES_FLOAT) else claripy.ast.bv.BV
                func_cc = self.proj.factory.cc_from_arg_kinds([typ in C_TYPES_FLOAT for typ in func_arg_types], ret_fp=func_ret_type in C_TYPES_FLOAT)
                func_op = None
                if len(func_arg_types) > 0:
                    func_op = claripy.operations.op(func_name, func_op_arg_types, func_op_ret_type, do_coerce=False, calc_length=lambda *x: c_type_to_bit_size(func_ret_type))

                def call_hook(state):
                    arg_locs = func_cc.args
                    if len(arg_locs) == 0:
                        ret_bvs = claripy.BVS(name=func_name, explicit_name=True, size=func_cc.ret_val.size)
                        func_cc.ret_val.set_value(state, ret_bvs)
                    else:
                        claripy_args = []
                        for arg_loc in arg_locs:
                            arg = arg_loc.get_value(state)
                            claripy_arg = arg.to_claripy()
                            if func_cc.is_fp_arg(arg_loc):
                                claripy_arg = claripy_arg[double_length-1:0].raw_to_fp()
                            claripy_args.append(claripy_arg)
                        #print('ret reg: {}'.format(func_cc.ret_val))
                        #state.regs.rax = func_op(*claripy_args)
                        func_cc.ret_val.set_value(state, func_op(*claripy_args))
                self.proj.hook(call_insn_addr, hook=call_hook, length=func.instruction_size(call_insn_addr))




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

    def eval(self, maps):
        solver = claripy.Solver()
        return solver.eval(self.symex_expr, 1, extra_constraints=[var == val for var, val in maps.items()])


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
        log.warning("Legacy: Only infix is used now")
        symex_expr = self.symex_expr
        prefix = self._symex_to_prefix(symex_expr)

        if use_heuristics and \
           len(prefix) > 2 and \
           prefix[0] == "Concat" and \
           prefix[1].startswith("reg_"):
            prefix = prefix[2:]

        return [_process_token(elem) for elem in prefix]


    def _symex_to_infix_tree(self, expr, use_heuristics=True):
        if not hasattr(expr, "op"):
            return InfixTree(expr=str(expr))
        op = str(expr.op)

        if op == "BVV":
            # Constant value
            return InfixTree(expr=str(hex(expr.args[0])))

        elif op == "Concat":
            # Handle special case of
            # (a[7:0] .. a[15:8] .. a[23:16] .. a[31:24])
            # If not this case, do nothing here
            queue = self._try_merge_same_variable_concat(list(expr.args))
            if queue is not None:
                return InfixTree(expr=queue[0])
            if use_heuristics:
                # Merge SignExt (a[31:0] >> 0x1f .. a[31:0])
                if hasattr(expr.args[0], "op") and str(expr.args[0].op) == "__rshift__":
                    child1 = expr.args[0].args[0]
                    child2 = expr.args[1]
                    if (child1 == child2).is_true():
                        return self._symex_to_infix_tree(child1)

                # Merge ZeroExt
                if hasattr(expr.args[0], "op") and str(expr.args[0].op) == "BVV":
                    if str(hex(expr.args[0].args[0])) == "0x0":
                        return self._symex_to_infix_tree(expr.args[1])

                # For case <BV128 (0x0 .. fpToIEEEBV()[127:32] .. fpToIEEEBV())>
                # Only return the first fpToIEEEBV()
                if len(expr.args) == 2 and \
                   hasattr(expr.args[0], "op") and str(expr.args[0].op) == "Extract" and \
                   expr.args[0].args[0] == 127 and expr.args[0].args[1] == 32 and \
                   hasattr(expr.args[1], "op") and expr.args[1].op == "fpToIEEEBV":
                    return self._symex_to_infix_tree(expr.args[0].args[2])

        elif op == "Extract":
            if not use_heuristics:
                ch1 = str((expr.args[0], expr.args[1]))
                ch2 = self._symex_to_infix_tree(expr.args[2])
                return InfixTree(op=op, children=[ch1, ch2])
            else:
                # Discard "Extract" expression
                return self._symex_to_infix_tree(expr.args[2])

        elif (op == "ZeroExt" or op == "SignExt") and use_heuristics:
            return self._symex_to_infix_tree(expr.args[1])

        elif op == "fpToIEEEBV" or op == "FPS" or op == "FPV":
            return self._symex_to_infix_tree(expr.args[0])

        elif op == "fpToFP":
            if isinstance(expr.args[0], claripy.fp.RM):
                return self._symex_to_infix_tree(expr.args[1])
            else:
                return self._symex_to_infix_tree(expr.args[0])

        elif op == "BVS":
            # FIXME:
            # if <use_heuristic>, we extracted variable at "Extract", won't execute here
            return InfixTree(expr=str(expr.args[0]))

        elif op == "fpAdd" or \
                op == "fpSub" or \
                op == "fpMul" or \
                op == "fpDiv":
            children = [self._symex_to_infix_tree(expr.args[1]), self._symex_to_infix_tree(expr.args[2])]
            return InfixTree(op=op, children=children)

        elif op == "fpNeg":
            children = [self._symex_to_infix_tree(expr.args[0])]
            return InfixTree(op="-", children=children)

        elif op in SYM_UNFUNCS_d:
            children = [self._symex_to_infix_tree(expr.args[0])]
            return InfixTree(op=SYM_UNFUNCS_d[op], children=children)

        elif op in SYM_BINFUNCS_d:
            children = [self._symex_to_infix_tree(expr.args[0]), self._symex_to_infix_tree(expr.args[1])]
            return InfixTree(op=SYM_BINFUNCS_d[op], children=children)

        else:
            log.debug("Symexpr use default handling: %s, args: %s" % (op, len(expr.args)))

        children = []
        ast_queue = deque([iter(expr.args)])
        while ast_queue:
            try:
                ast = next(ast_queue[-1])
            except StopIteration:
                ast_queue.pop()
                continue
            children.append(self._symex_to_infix_tree(ast))
        return InfixTree(op=op, children=children)


    def symex_to_infix(self, use_heuristics=True):
        symex_expr = self.symex_expr
        infix_tree = self._symex_to_infix_tree(symex_expr)

        return infix_tree.get_sequence(use_heuristics)


def _put_brackets(children):
    if len(children) > 1 and \
       not (children[0] == "(" and children[-1] == ")"):
        return ["("] + children + [")"]
    return children


class InfixTree:
    def __init__(self, expr=None, op=None, children=[]):
        self.expr = expr
        self.op = op
        self.children = children

    def __str__(self):
        if self.op is not None:
            return self.op + "(" + ",".join(str(ch) for ch in self.children) + ")"
        else:
            return self.expr

    def sequenize(self):
        if self.op is None:
            return [_process_token(self.expr)]
        op = _process_token(self.op)
        if op == "-" and len(self.children) == 1:
            return ["-"] + _put_brackets(self.children[0].sequenize())
        if op in SYM_BINOPS:
            ret = _put_brackets(self.children[0].sequenize())
            for child in self.children[1:]:
                ret += [op]
                ret += _put_brackets(child.sequenize())
            return ret
        else:
            ret = [op, "("] + self.children[0].sequenize()
            for child in self.children[1:]:
                ret += [","]
                ret += _put_brackets(child.sequenize())
            ret += [")"]
        return ret

    def get_sequence(self, use_heuristics=True):
        if use_heuristics and \
           len(self.children) == 2 and \
           self.op == "Concat" and \
           self.children[0].expr is not None and \
           self.children[0].expr.startswith("reg_"):
            return self.children[1].sequenize()
        else:
            return self.sequenize()
