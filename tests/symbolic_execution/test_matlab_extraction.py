from nose.tools import *
import matlab.engine

import os
import tempfile

from expression.components import *
from .test_symbolic_expression_extraction import eval_int_expr


# Generate a MATLAB C++ function given a test string and a MATLAB execution engine
def generate_matlab_function(matlab_command, eng):
    work_dir = tempfile.mkdtemp()
    matlab_src = os.path.join(work_dir, 'test.m')

    with open(matlab_src, 'w') as f:
        f.write('function poly = test(A, B)\n')
        f.write('    ' + matlab_command + '\n')
        f.write('end')

    eng.cd(work_dir, nargout=1)
    eng.codegen('-config:lib', matlab_src, '-args', '{1, 1}')
    return os.path.join(work_dir, 'codegen', 'lib', 'test', 'test.o')


# Test the engine generation with a simple expression
def test_simple():
    eng = matlab.engine.start_matlab()
    print(generate_matlab_function('poly = A * B + 2', eng))
    print(generate_matlab_function('poly = exp(A) * B ^ 2', eng))
    print(generate_matlab_function('poly = A ^ B', eng))
    print(generate_matlab_function('poly = log10(A)', eng))
    print(generate_matlab_function('poly = 0', eng))
    print(generate_matlab_function('poly = sqrt(A + B)', eng))


if __name__ == "__main__":
    test_simple()
