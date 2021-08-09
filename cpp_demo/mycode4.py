import pyvex
import claripy
import angr


target_func = "_ZN18AP_SteerController14simple_compareEf"
var_names = ['this', 'desired_rate']
var_ctypes = ['int', 'float']
ret_type = "float"

groundspeed_map = (0x601070, ('groundspeed', (), 'float'))
sqrtf = (0x500000, ('sqrtf', ('float', 'float'), 'float'))
short_circuit_calls = dict((groundspeed_map, sqrtf))

see = SymbolicExpressionExtractor("cpp_demo/AP_SteerController.o")
start_state = see.extract(target_func, var_names, var_ctypes, ret_type, False, short_circuit_calls=short_circuit_calls)

state = start_state.copy()
"""
state.mem[state.regs.rdi+0x14].float = claripy.FPS("rdi+0x14", claripy.fp.FSORT_FLOAT, explicit_name=True)
state.mem[state.regs.rdi+0x30].uint64_t = claripy.BVS("rdi+0x30", 64, explicit_name=True)
state.mem[state.mem[state.regs.rdi+0x30].uint64_t.resolved].uint64_t = claripy.BVS("*(rdi+0x30)", 64, explicit_name=True)
state.mem[state.mem[state.mem[state.regs.rdi+0x30].uint64_t.resolved].uint64_t.resolved+0x10].uint64_t = 0x601050
"""
state.mem[state.regs.rdi+0x14].float = claripy.FPS("rdi+0x14", claripy.fp.FSORT_FLOAT, explicit_name=True)




o_state = state

"""
succ = state.step()
while len(succ.successors) == 1:
    state = succ.successors[0]
    succ = state.step()

state1, state2 = succ.successors

"""