from abc import ABC, abstractmethod

#######################################
# Lists of Operators & Math Functions
#   Format: (class name, math symbol/function name)
#######################################

# Operand types
OP_TYPE_NUM = "num" # Operands can be any number
OP_TYPE_INT = "int" # Operands must be integers
OP_TYPE_LNG = "long" # Operands must be longs
OP_TYPE_DBL = "double" # Operands must be doubles

# Unary Operators
UNARY_OPERATORS = [("NegOp", "-", OP_TYPE_NUM)]

# Binary Operators
BINARY_OPERATORS = [("AddOp", "+", OP_TYPE_NUM),
       ("SubOp", "-", OP_TYPE_NUM),
       ("MulOp", "*", OP_TYPE_NUM),
       ("DivOp", "/", OP_TYPE_NUM),
       ("ModOp", "%", OP_TYPE_INT)]

BINARY_BIT_OPERATORS = [("AndOp", "&", OP_TYPE_INT),
       ("OrOp", "|", OP_TYPE_INT),
       ("XorOp", "^", OP_TYPE_INT),
       ("LshiftOp", "<<", OP_TYPE_INT),
       ("RshiftOp", ">>", OP_TYPE_INT)]

# Unary Functions
# https://en.wikibooks.org/wiki/C_Programming/math.h
UNARY_FUNCTIONS = [("AbsFunc", "abs", OP_TYPE_INT),
       ("LabsFunc", "labs", OP_TYPE_LNG),
       ("AcosFunc", "acos", OP_TYPE_DBL),
       ("AsinFunc", "asin", OP_TYPE_DBL),
       ("AtanFunc", "atan", OP_TYPE_DBL),
       ("CeilFunc", "ceil", OP_TYPE_DBL),
       ("CosFunc", "cos", OP_TYPE_DBL),
       ("CoshFunc", "cosh", OP_TYPE_DBL),
       ("CbrtFunc", "cbrt", OP_TYPE_DBL),
       ("ExpFunc", "exp", OP_TYPE_DBL),
       ("FabsFunc", "fabs", OP_TYPE_DBL),
       ("FloorFunc", "floor", OP_TYPE_DBL),
       ("LogFunc", "log", OP_TYPE_DBL),
       ("Log10Func", "log10", OP_TYPE_DBL),
       ("SinFunc", "sin", OP_TYPE_DBL),
       ("SinhFunc", "sinh", OP_TYPE_DBL),
       ("SqrtFunc", "sqrt", OP_TYPE_DBL),
       ("TanFunc", "tan", OP_TYPE_DBL),
       ("TanhFunc", "tanh", OP_TYPE_DBL),
       ("AcoshFunc", "acosh", OP_TYPE_DBL),
       ("AsinhFunc", "asinh", OP_TYPE_DBL),
       ("AtanhFunc", "atanh", OP_TYPE_DBL),
       ("AtanhFunc", "atanh", OP_TYPE_DBL),
       ("Exp2Func", "exp2", OP_TYPE_DBL),
       ("Log2Func", "log2", OP_TYPE_DBL),
       ("TgammaFunc", "tgamma", OP_TYPE_DBL)]

# Binary Functions
BINARY_FUNCTIONS = [("PowFunc", "pow", OP_TYPE_DBL)]

# Ignore TernaryOperator for now since there seems to be only a few of them

#######################################
# Abstract classes
#######################################
class Node(ABC):
    def __init__(self, *children):
        self.children = children
        self.num_children = len(children)
        self.leaves = None

    def get_leaves(self):
        if self.leaves is None:
            self.leaves = []
            Node._get_leaves(self, self.leaves)
        return self.leaves

    def _get_leaves(node, leaves):
        if isinstance(node, Leaf):
            leaves.append(node)
            return

        for child in node.children:
            Node._get_leaves(child, leaves)

    def to_c(self):
        return str(self)
    
    @abstractmethod
    def __str__(self):
        pass


class Leaf(Node):
    num_children = 0
    def __init__(self, *children):
        super().__init__()


class Operator(Node):
    def __init__(self, op, op_type, *children):
        super().__init__(*children)
        self.op = op
        self.op_type = op_type


class Function(Node):
    def __init__(self, func_name, arg_type, *children):
        super().__init__(*children)
        self.func_name = func_name
        self.arg_type = arg_type

    def __str__(self):
        return "{}({})".format(self.func_name, ', '.join(str(child) for child in self.children))


class UnaryFunction(Function):
    num_children = 1
    def __init__(self, op, arg_type, child):
        super().__init__(op, arg_type, child)
        self.num_children = 1


class BinaryFunction(Function):
    num_children = 2
    def __init__(self, op, op_type, arg1, arg2):
        super().__init__(op, op_type, arg1, arg2)
        self.num_children = 2


class UnaryOperator(Operator):
    num_children = 1
    def __init__(self, op, op_type, arg):
        super().__init__(op, op_type, arg)
        self.arg = arg

    def __str__(self):
        return "({}{})".format(self.op, str(self.arg))


class BinaryOperator(Operator):
    num_children = 2
    def __init__(self, op, op_type, left, right):
        super().__init__(op, op_type, left, right)
        self.left = left
        self.right = right

    def __str__(self):
        return "({} {} {})".format(self.left, self.op, self.right)


class TernaryOperator(Operator):
    num_children = 3
    def __init__(self, op, op_type, left, mid, right):
        super().__init__(op, op_type, left, mid, right)
        self.left = left
        self.mid = mid
        self.right = right


class Const(Leaf):
    def __init__(self, num):
        super().__init__()
        self.num = num

    def __str__(self):
        return str(self.num)

class Var(Leaf):
    def __init__(self, name):
        super().__init__()
        self.name = name

    def __str__(self):
        return str(self.name)


#######################################
# Generate Operators & Functions class
#######################################
def make_classes(method, op, op_type, classname):
    code = "class %s(%s):\n" % (method, classname)
    code += "   def __init__(self, *arg):\n"
    code += "       super().__init__('%s', '%s', *arg)\n" % (op, op_type)
    locals_dict = {}
    exec(code, globals(), locals_dict)
    globals()[method] = locals_dict[method]

for (name, op, op_type) in UNARY_OPERATORS:
    make_classes(name, op, op_type, "UnaryOperator")

for (name, op, op_type) in BINARY_OPERATORS:
    make_classes(name, op, op_type, "BinaryOperator")

for (name, op, op_type) in BINARY_BIT_OPERATORS:
    make_classes(name, op, op_type, "BinaryOperator")

for (name, func_name, arg_type) in UNARY_FUNCTIONS:
    make_classes(name, func_name, arg_type, "UnaryFunction")

for (name, func_name, arg_type) in BINARY_FUNCTIONS:
    make_classes(name, func_name, arg_type, "BinaryFunction")





