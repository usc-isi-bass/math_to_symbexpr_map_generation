from collections.abc import Iterable

from expression.components import *
from code_generation.code_templates import C_CODE_TEMPLATE

#######################################
#
# Generate C code containing a given mathematical expression.
#
#######################################
class CCodeGenerator:

    #######################################
    #
    # CCodeGenerator(expression)
    #    +-     expression: The expression to wrap in the C code.
    #
    #######################################

    def __init__(self, expression: Node, ret_type="int"):
        if ret_type not in C_TYPES:
            print("Wrong return type for generating C code")
            return None
        self.ret_type = ret_type
        self.template = C_CODE_TEMPLATE
        self.expression = expression
        self.vars = self._get_vars()
        self.var_names = [var.name for var in self.vars]
        self.var_ctypes = [var.c_type for var in self.vars]
        self.num_vars = len(self.vars)


    def generate_code(self):
        '''
        Generate the C code
        Return:
            The generated C code as a GeneratedCCode object.
        '''

        # Generate code for each of the tags required by C_CODE_TEMPLATE
        template_args = {
            'f_sig_ret': self._gen_f_sig_ret(),
            'f_sig_print': self._gen_f_sig_print(),
            'f_sig_name': self._gen_f_sig_name(),
            'f_sig_args': self._gen_f_sig_args(),
            'f_expr': self._gen_f_expr(),
            'argc_min': self._gen_argc_min(),
            'usage_msg': self._gen_usage_msg(),
            'f_call_args': self._gen_f_call_args()
        }

        c_code = self.template.format(**template_args)
        wrapper_func = template_args['f_sig_name']

        generated_c_code = GeneratedCCode(wrapper_func, self.expression, self.var_names, self.var_ctypes, c_code)



        return generated_c_code

    def _get_vars(self):
        vars_l  = []
        vars_s = set()
        # Find unique variables in the leaves, and keep the order from left to right.
        for var in filter(lambda l: isinstance(l, Var), self.expression.get_leaves()):
            if var not in vars_s:
                vars_s.add(var)
                vars_l.append(var)
        return vars_l


    def _gen_f_sig_print(self):
        # The return value type of the wrapper function.
        if self.ret_type == "int" or self.ret_type == "unsigned int":
            return '%d'
        elif self.ret_type == "long" or self.ret_type == "unsigned long":
            return '%ld'
        else:
            return '%f'

    def _gen_f_sig_ret(self):
        # The return value type of the wrapper function.
        return self.ret_type

    def _gen_f_sig_name(self):
        # The name of the wrapper function
        return 'f_{:03d}'.format(self.num_vars)

    def _gen_f_sig_args(self):
        # The arguments of the wrapper function's signature.
        ret_str = ""
        for arg in self.vars:
            ret_str += "{} {}, ".format(arg.c_type, arg.name)
        return ret_str[0:-2]

    def _gen_f_expr(self):
        # The C representation of the signature to wrap in the code.
        return str(self.expression)

    def _gen_argc_min(self):
        # The minimum number of command line arguments required (argc must be +1 more than the number of variables).
        return str(self.num_vars + 1) # (argc must be +1 more than the number of variables)

    def _gen_usage_msg(self):
        # A usage message to display after "usage: argv[0] "
        return ' '.join(var.name for var in self.vars)

    def _gen_f_call_args(self):
        # The arguments to pass the wrapper function.
        ret_str = ""
        args = self.vars
        for i in range(1, self.num_vars + 1):
            if args[i-1].c_type in C_TYPES_INT:
                ret_str += "atoi(argv[{}]), ".format(i)
            else:
                ret_str += "atof(argv[{}]), ".format(i)
        return ret_str[0:-2]

class GeneratedCCode:
    #######################################
    #
    # GeneratedCCode(wrapper_func, code)
    #    An object to hold the generated C code.
    #    +-     wrapper_func: The name of the function housing the expression as a str.
    #    +-     expr:         The expression wrapped into the code.
    #    +-     code:         The C code as a str
    #
    #######################################

    def __init__(self, wrapper_func: str, expr: Node, expr_var_names: Iterable, expr_var_ctypes: Iterable, code: str):
        self.wrapper_func = wrapper_func
        self.expr = expr
        self.expr_var_names = expr_var_names
        self.expr_var_ctypes = expr_var_ctypes
        self.code = code
