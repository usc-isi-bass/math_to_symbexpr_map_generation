from expression.components import *
from code_generation.c_code_generation import CCodeGenerator

def main():
    c1 = Const(2)
    c2 = Const(3)
    c3 = Const(4)
    v1 = Var('b', "unsigned long")
    v2 = Var('c', "float")
    v3 = Var('d', "double")
    v4 = Var('e')
    expr = AddOp(SubOp(c1, DivOp(v1, NegOp(c2))), MulOp(AbsFunc(PowFunc(v2, c3)), SqrtFunc(v4)))
    ccg = CCodeGenerator(expr, ret_type="float")
    print(ccg.generate_code().code)

    

if __name__ == "__main__":
    main()
