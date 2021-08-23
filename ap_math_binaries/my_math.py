import pyvex
import claripy
import angr



# ardupilot/libraries/AP_Math/AP_Math.cpp:88
target_func = "_Z18linear_interpolatefffff"
var_names = ["low_output", "high_output", "var_value", "var_low", "var_high"]
var_ctypes = ["float", "float", "float", "float", "float"]
ret_type = "float"
short_circuit_calls = dict()

see = SymbolicExpressionExtractor("ap_math_binaries/AP_Math.cpp.0.o")
rets = see.extract_allstates(target_func, var_names, var_ctypes, ret_type, False, short_circuit_calls=short_circuit_calls)

#print(rets)

for group in rets:
    print(group[0])
    print("".join(e for e in group[1]))

print("------------------------------")
"""

# ardupilot/libraries/AP_Math/AP_Math.cpp:116
target_func = "_Z14throttle_curvefff"
var_names = ["thr_mid", "alpha", "thr_in"]
var_ctypes = ["float", "float", "float"]
ret_type = "float"
short_circuit_calls = dict()

see = SymbolicExpressionExtractor("ap_math_binaries/AP_Math.cpp.0.o")
rets = see.extract_allstates(target_func, var_names, var_ctypes, ret_type, False, short_circuit_calls=short_circuit_calls)

print(rets)

for group in rets:
    print(group[0])
    print("".join(e for e in group[1]))
"""
