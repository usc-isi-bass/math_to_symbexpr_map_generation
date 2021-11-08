import angr
import argparse
import claripy
import logging
import os

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor

def main():
    elf_path = 'perfume_paper_examples'
    see  = SymbolicExpressionExtractor(elf_path)
    #fib_map = (0x400878, ('fib', ('int',), 'int'))


    #short_circuit_calls=dict((fib_map,))
    short_circuit_calls = {}
    extracted_symexpr = see.extract('f_001', ['a', 'b'], ['float', 'float'], 'float', simplified=False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    #print(ast)
    in_sym = extracted_symexpr.symex_to_infix()
    print("")
    print("".join(in_sym))
    extracted_symexpr = see.extract('f_002', ['a', 'b'], ['float', 'int'], 'float', simplified=False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    #print(ast)
    in_sym = extracted_symexpr.symex_to_infix()
    print("")
    print("".join(in_sym))
    extracted_symexpr = see.extract('f_003', ['a', 'b', 'c'], ['float', 'float', 'float'], 'float', simplified=False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    #print(ast)
    in_sym = extracted_symexpr.symex_to_infix()
    print("")
    print("".join(in_sym))
    extracted_symexpr = see.extract('f_004', ['a', 'b', 'c'], ['float', 'float', 'float'], 'float', simplified=False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    #print(ast)
    in_sym = extracted_symexpr.symex_to_infix()
    print("")
    print("".join(in_sym))

    extracted_symexpr = see.extract('f_005', ['a', 'b'], ['int', 'int'], 'int', simplified=False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    #print(ast)
    in_sym = extracted_symexpr.symex_to_infix()
    print("")
    print("".join(in_sym))

    extracted_symexpr = see.extract('f_006', ['a', 'b'], ['float', 'float'], 'float', simplified=False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    solver = claripy.Solver()
    #print(solver.eval(ast, 1, extra_constraints=[var == 1.0 for var in extracted_symexpr.symvars]))
    #print(ast)
    #print(extracted_symexpr.symvars)
    #print(solver.eval(ast, 1, extra_constraints=[var == claripy.ast.fp.FPV(2.0 + i, sort=claripy.FSORT_DOUBLE) for i, var in enumerate(extracted_symexpr.symvars)]))

    #print(ast.eval({var: 1 for var in extracted_symexpr.symvars}))
    #print(ast)
    in_sym = extracted_symexpr.symex_to_infix()
    print("")
    print("".join(in_sym))

if __name__ == '__main__':
    main()
