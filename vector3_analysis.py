import angr
import logging

from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False



def main():
    elf_path = 'vector3'
    see  = SymbolicExpressionExtractor(elf_path)



    func_name = 'v3_cross1'
    short_circuit_calls = {}
    extracted_symexpr = see.extract(func_name, ['x', 'y', 'out'], ['int', 'int', 'int'], 'int', simplified=False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    print(ast)
    print("")

    func_name = 'v3_cross2'
    #short_circuit_calls = {0x400797:('vector3', ('int', 'int', 'int'), 'int')}
    extracted_symexpr = see.extract(func_name, ['x', 'y'], ['int', 'int'], 'int', simplified=False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    print(ast)


if __name__ == "__main__":
    main()
