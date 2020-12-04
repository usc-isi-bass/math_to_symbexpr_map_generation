from abc import ABC, abstractmethod


# XXX When we add booleans, we should add something like children types to indicate what type (number or boolean) each child should be. We should also add what type every operator and function returns
# Abstract classes

class Node(ABC):

    def __init__(self, *children):
        self.children = children
        self.num_children = len(children)
    
    @abstractmethod
    def to_c(self):
        pass

class Operator(Node):

    def __init__(self, op, *children):
        super().__init__(*children)
        self.op = op

class FuncOperator(Operator):
    
    def __init__(self, func_name, *children):
        super().__init__(func_name, *children)
        self.func_name = self.op

    def to_c(self):
        return "{}({})".format(self.func_name, ', '.join(child.to_c() for child in self.children))
        

class TernaryOperator(Operator):
    num_children = 3

    def __init__(self, op, left, mid, right):
        super().__init__(op, left, mid, right)
        self.left = left
        self.mid = mid
        self.right = right

class BinaryOperator(Operator):
    num_children = 2

    def __init__(self, op, left, right):
        super().__init__(op, left, right)
        self.left = left
        self.right = right

    def to_c(self):
        return "({} {} {})".format(self.left.to_c(), self.op, self.right.to_c())

class UnaryOperator(Operator):
    num_children = 1

    def __init__(self, op, child):
        super().__init__(op, child)
        self.child = child

    def to_c(self):
        return "({}{})".format(self.op, self.child.to_c())

class Leaf(Node):
    num_children = 0
    

# Concrete operators

class AddOp(BinaryOperator):

    def __init__(self, left, right):
        super().__init__('+', left, right)

class SubOp(BinaryOperator):

    def __init__(self, left, right):
        super().__init__('-', left, right)

class MulOp(BinaryOperator):

    def __init__(self, left, right):
        super().__init__('*', left, right)

class DivOp(BinaryOperator):

    def __init__(self, left, right):
        super().__init__('/', left, right)

class ModOp(BinaryOperator):

    def __init__(self, left, right):
        super().__init__('%', left, right)

class NegOp(UnaryOperator):

    def __init__(self, child):
        super().__init__('-', child)


class PowOp(FuncOperator):
    num_children = 2

    def __init__(self, arg1, arg2):
        super().__init__('pow', arg1, arg2)

class SqrtOp(FuncOperator):
    num_children = 1

    def __init__(self, arg1):
        super().__init__('sqrt', arg1)

# Concrete leaves
        
# XXX Do we need two of these?
class Const(Leaf):
    def __init__(self, num):
        super().__init__()
        self.num = num

    def to_c(self):
        return str(self.num)

class Var(Leaf):
    def __init__(self, name):
        super().__init__()
        self.name = name

    def to_c(self):
        return str(self.name)



