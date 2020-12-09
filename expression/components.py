from abc import ABC, abstractmethod

#######################################
# Lists of Operators & Math Functions
#   Format: (class name, math symbol/function name, (arg_type, return_type))
#     |+ arg_type: requirement type for this operator/function
#     |+ return_type: return type for this operator/function
#        None stands for any given type
#######################################

# Unary Operators
UNARY_OPERATORS = [("NegOp", "-", (None, None))]

# Binary Operators
BINARY_OPERATORS = [("AddOp", "+", (None, None)),
       ("SubOp", "-", (None, None)),
       ("MulOp", "*", (None, None)),
       ("DivOp", "/", (None, None)),
       ("ModOp", "%", ("int", "int"))]

BINARY_BIT_OPERATORS = [("AndOp", "&", ("int", "int")),
       ("OrOp", "|", ("int", "int")),
       ("XorOp", "^", ("int", "int")),
       ("LshiftOp", "<<", ("int", "int")),
       ("RshiftOp", ">>", ("int", "int"))]

# Unary Functions
# https://en.wikibooks.org/wiki/C_Programming/math.h
UNARY_FUNCTIONS = [("AbsFunc", "abs", (None, None)),
       ("AcosFunc", "acos", (None, "double")),
       ("AsinFunc", "asin", (None, "double")),
       ("AtanFunc", "atan", (None, "double")),
       ("CeilFunc", "ceil", (None, "double")),
       ("CosFunc", "cos", (None, "double")),
       ("CoshFunc", "cosh", (None, "double")),
       ("CbrtFunc", "cbrt", (None, "double")),
       ("ExpFunc", "exp", (None, "double")),
       ("FabsFunc", "fabs", (None, "double")),
       ("FloorFunc", "floor", (None, "double")),
       ("LogFunc", "log", (None, "double")),
       ("Log10Func", "log10", (None, "double")),
       ("SinFunc", "sin", (None, "double")),
       ("SinhFunc", "sinh", (None, "double")),
       ("SqrtFunc", "sqrt", (None, "double")),
       ("TanFunc", "tan", (None, "double")),
       ("TanhFunc", "tanh", (None, "double")),
       ("AcoshFunc", "acosh", (None, "double")),
       ("AsinhFunc", "asinh", (None, "double")),
       ("AtanhFunc", "atanh", (None, "double")),
       ("AtanhFunc", "atanh", (None, "double")),
       ("Exp2Func", "exp2", (None, "double")),
       ("Log2Func", "log2", (None, "double")),
       ("TgammaFunc", "tgamma", (None, "double"))]

# Binary Functions
BINARY_FUNCTIONS = [("PowFunc", "pow", (None, "double"))]

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
    def __init__(self, op, *children):
        super().__init__(*children)
        self.op = op


class Function(Node):
    def __init__(self, func_name, *children):
        super().__init__(*children)
        self.func_name = func_name

    def __str__(self):
        return "{}({})".format(self.func_name, ', '.join(str(child) for child in self.children))


class UnaryFunction(Function):
    num_children = 1
    def __init__(self, op, child):
        super().__init__(op, child)
        self.num_children = 1


class BinaryFunction(Function):
    num_children = 2
    def __init__(self, op, arg1, arg2):
        super().__init__(op, arg1, arg2)
        self.num_children = 2


class UnaryOperator(Operator):
    num_children = 1
    def __init__(self, op, arg):
        super().__init__(op, arg)
        self.arg = arg

    def __str__(self):
        return "({}{})".format(self.op, str(self.arg))


class BinaryOperator(Operator):
    num_children = 2
    def __init__(self, op, left, right):
        super().__init__(op, left, right)
        self.left = left
        self.right = right

    def __str__(self):
        return "({} {} {})".format(self.left, self.op, self.right)


class TernaryOperator(Operator):
    num_children = 3
    def __init__(self, op, left, mid, right):
        super().__init__(op, left, mid, right)
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

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)


#######################################
# Generate Operators & Functions class
#######################################
def make_classes(method, op, classname):
    code = "class %s(%s):\n" % (method, classname)
    code += "   def __init__(self, *arg):\n"
    code += "       super().__init__('%s', *arg)\n" % op
    locals_dict = {}
    exec(code, globals(), locals_dict)
    globals()[method] = locals_dict[method]

for (name, op, _) in UNARY_OPERATORS:
    make_classes(name, op, "UnaryOperator")

for (name, op, _) in BINARY_OPERATORS:
    make_classes(name, op, "BinaryOperator")

for (name, op, _) in BINARY_BIT_OPERATORS:
    make_classes(name, op, "BinaryOperator")

for (name, func_name, _) in UNARY_FUNCTIONS:
    make_classes(name, func_name, "UnaryFunction")

for (name, func_name, _) in BINARY_FUNCTIONS:
    make_classes(name, func_name, "BinaryFunction")





