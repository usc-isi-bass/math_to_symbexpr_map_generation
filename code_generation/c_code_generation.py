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

    def __init__(self, expression: Node):
        self.template = C_CODE_TEMPLATE
        self.expression = expression
        self.vars = list(self._get_vars())
        self.var_names = [var.name for var in self.vars]
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
            'f_sig_name': self._gen_f_sig_name(),
            'f_sig_args': self._gen_f_sig_args(),
            'f_expr': self._gen_f_expr(),
            'argc_min': self._gen_argc_min(),
            'usage_msg': self._gen_usage_msg(),
            'f_call_args': self._gen_f_call_args()
        }

        c_code = self.template.format(**template_args)
        wrapper_func = template_args['f_sig_name']

        generated_c_code = GeneratedCCode(wrapper_func, self.expression, self.var_names, c_code)



        return generated_c_code

    def _get_vars(self):
        return filter(lambda l: isinstance(l, Var), self.expression.get_leaves())


    def _gen_f_sig_ret(self):
        # The return value type of the wrapper function.
        return 'int'

    def _gen_f_sig_name(self):
        # The name of the wrapper function
        return 'f_{:03d}'.format(self.num_vars)

    def _gen_f_sig_args(self):
        # The arguments of the wrapper function's signature.
        return ', '.join("int {}".format(var_name) for var_name in self.var_names)

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
        return ', '.join('atoi(argv[{}])'.format(i) for i in range(1, self.num_vars + 1))

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

    def __init__(self, wrapper_func: str, expr: Node, expr_var_names: Iterable, code: str):
        self.wrapper_func = wrapper_func
        self.expr = expr
        self.expr_var_names = expr_var_names
        self.code = code
