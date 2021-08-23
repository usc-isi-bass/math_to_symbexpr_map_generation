
from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor

target_func = "_ZN18AP_SteerController13simple_returnEf"
var_names = ['this', 'desired_rate']
var_ctypes = ['int', 'float']
ret_type = "float"

# Define a function manually, don't think it's the groundspeed() though
short_circuit_calls = {0x601070: ('groundspeed', (), 'float')}

see = SymbolicExpressionExtractor("simplified_ardupilot/AP_SteerController.o")
# NOTE: I wrapped .extract() with .extract_allstates() and .extract_merged() to
#       handle different potential future requirements
# NOTE: I add an additional option in extract_allstates() to init memory location
#       of function call manually in symbolic_execution/symbolic_expression_extraction.py
rets = see.extract_allstates(target_func, var_names, var_ctypes, ret_type, False, short_circuit_calls=short_circuit_calls,
                         ardupilot_demo=True)

for jump_guards, ret_expr in rets:
    print(jump_guards)
    print('-')
    print("".join(e for e in ret_expr))
    print("======")
