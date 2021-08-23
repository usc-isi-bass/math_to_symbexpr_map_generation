import angr
import pyvex

proj = angr.Project("AP_SteerController.o", load_options={'auto_load_libs': False})
cfg = proj.analyses.CFGFast()

with open("./bt_func.py", "r") as fd:
    c = fd.read()
    exec(c)

calling_nodes = []

for node in cfg.model.nodes():
    # Check if this block calls other functions
    for succ, jump_kind in node.successors_and_jumpkinds():
        if jump_kind == "Ijk_Call":
            calling_nodes.append(node)
        break
        

for node in calling_nodes:
    print(node.name)
    print("-")
    node.block.pp()
    print("-")
    node.block.vex.pp()
    print("-")
    if type(node.block.vex.next) != pyvex.expr.Const:
        print("Next: %s " % node.block.vex.next)
        print(get_jump_call_location(proj, node.block))
    else:
        print("Next: %s " % node.block.vex.next)

    print("==============")
