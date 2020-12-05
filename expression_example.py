from expression.components import *

expr = MulOp(Var('a'), Var('b'))
print(expr)

expr2 = SinFunc(expr)
print(expr2)
print(isinstance(expr2, BinaryOperator))
print(isinstance(expr2, UnaryFunction))

expr3 = MinusOp(expr)
expr4 = AddOp(expr2, expr3)
print(expr4)
print(expr4.num_children)
print(expr4.children[1])

