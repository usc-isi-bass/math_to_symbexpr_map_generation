import os

from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'binaries', 'test_binaries')

def main():
    elf_name = 'test_if'
    elf_path = os.path.join(test_location, elf_name)
    func_name = 'f_if'
    var_ctypes = ['int', 'int']
    see = SymbolicExpressionExtractor(elf_path)
    func = see.cfg.functions.function(name=func_name)
    arg1, arg2 = 'argb1', 'argi2'
    extracted_symexpr = see.extract(func_name, [arg1,arg2], var_ctypes, "int")
    symex_expr = extracted_symexpr.symex_expr
    print(symex_expr)

if __name__ == "__main__":
    main()
