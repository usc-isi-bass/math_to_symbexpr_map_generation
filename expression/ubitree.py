
from .components import *
import numpy as np

#######################################
#
# Generate a tree of unary & binary operations.
#
# Using the code from
# Deep Learning for Symbolic Mathematics(ICLR 2020)
# https://arxiv.org/abs/1912.01412
# https://github.com/facebookresearch/SymbolicMathematics
#
#######################################


#######################################
#
# UbiTree(max_ops, num_leaves, max_int, <use_bit_op>)
#   +-     max_ops:  Create a tree with # operators/functions.
#   +-  num_leaves:  Number of leaves in tree (Ideally)
#   +-     max_int:  Maximum value of generated constant
#   +-  use_bit_op:  To include C bit operators or not (optional)
#
# List of operators/functions defined in components.py
#
#######################################
class UbiTreeGenerator():
    def __init__(self, max_ops, num_leaves, max_int, use_bit_op=False):
        unas = UNARY_OPERATORS + UNARY_FUNCTIONS
        if use_bit_op:
            bins = BINARY_OPERATORS + BINARY_BIT_OPERATORS + BINARY_FUNCTIONS
        else:
            bins = BINARY_OPERATORS + BINARY_FUNCTIONS
        ops = unas + bins
        self.all_ops = [o for o, _ in ops]
        self.una_ops = [o for o, _ in unas]
        self.bin_ops = [o for o, _ in bins]

        # generation parameters
        self.nl = num_leaves
        self.p1 = len(self.una_ops)
        self.p2 = len(self.bin_ops)
        self.max_int = max_int
        self.max_ops = max_ops

        self.ubi_dist = self._generate_ubi_dist(max_ops)
        self.rng = np.random.RandomState(np.random.randint(1_000_000_000))

    def _generate_ubi_dist(self, max_ops):
        """
        `max_ops`: maximum number of operators
        Enumerate the number of possible unary-binary trees that can be generated from empty nodes.
        D[e][n] represents the number of different binary trees with n nodes that
        can be generated from e empty nodes, using the following recursion:
            D(0, n) = 0
            D(e, 0) = L ** e
            D(e, n) = L * D(e - 1, n) + p_1 * D(e, n - 1) + p_2 * D(e + 1, n - 1)
        """
        # enumerate possible trees
        # first generate the tranposed version of D, then transpose it
        D = []
        D.append([0] + ([self.nl ** i for i in range(1, 2 * max_ops + 1)]))
        for n in range(1, 2 * max_ops + 1):  # number of operators
            s = [0]
            for e in range(1, 2 * max_ops - n + 1):  # number of empty nodes
                s.append(self.nl * s[e - 1] + self.p1 * D[n - 1][e] + self.p2 * D[n - 1][e + 1])
            D.append(s)
        assert all(len(D[i]) >= len(D[i + 1]) for i in range(len(D) - 1))
        D = [[D[j][i] for j in range(len(D)) if i < len(D[j])] for i in range(max(len(x) for x in D))]
        return D

    def _get_leaves(self, t_leaves, num_var, dup_var_prob, rng):
        """
        Generate a list of leaves.
        """
        leaves = []
        for cnt in range(t_leaves):
            if cnt < num_var:
                leaves.append("a_%s" % cnt)
                continue
            if num_var != 0:
                leaf_type = rng.choice(2, p=dup_var_prob)
            else:
                leaf_type = 1
            if leaf_type == 0:
                idx = rng.choice(num_var)
                leaves.append("a_%s" % idx)
            else:
                num = rng.choice(self.max_int)
                leaves.append(num)
        return leaves


    def _sample_next_pos_ubi(self, nb_empty, nb_ops):
        """
        Sample the position of the next node (unary-binary case).
        Sample a position in {0, ..., `nb_empty` - 1}, along with an arity.
        """
        assert nb_empty > 0
        assert nb_ops > 0
        probs = []
        for i in range(nb_empty):
            probs.append((self.nl ** i) * self.p1 * self.ubi_dist[nb_empty - i][nb_ops - 1])
        for i in range(nb_empty):
            probs.append((self.nl ** i) * self.p2 * self.ubi_dist[nb_empty - i + 1][nb_ops - 1])
        probs = [p / self.ubi_dist[nb_empty][nb_ops] for p in probs]
        probs = np.array(probs, dtype=np.float64)
        e = self.rng.choice(2 * nb_empty, p=probs)
        arity = 1 if e < nb_empty else 2
        e = e % nb_empty
        return e, arity

    def generate_ubitree_stack(self, num_var, dup_var_prob=[0.2, 0.8]):
        """
        Create a tree with exactly `self.max_ops` operators.
        Return format:
            [(Op name, # of children), ...]
        """
        rng = self.rng
        stack = [None]
        nb_empty = 1  # number of empty nodes
        l_leaves = 0  # left leaves - None states reserved for leaves
        t_leaves = 1  # total number of leaves (just used for sanity check)

        # create tree
        for nb_ops in range(self.max_ops, 0, -1):
            skipped, arity = self._sample_next_pos_ubi(nb_empty, nb_ops)
            if arity == 1:
                num_children = 1
                op = rng.choice(self.una_ops)
            else:
                num_children = 2
                op = rng.choice(self.bin_ops)

            # created empty nodes - skipped future leaves
            nb_empty += num_children - 1 - skipped  
            # update number of total leaves
            t_leaves += num_children - 1            
            # update number of left leaves
            l_leaves += skipped                           

            # update tree
            pos = [i for i, v in enumerate(stack) if v is None][l_leaves]
            stack = stack[:pos] + [(op, num_children)] + [None for _ in range(num_children)] + stack[pos + 1:]

        # sanity check
        assert len([1 for v in stack if v is not None and v[0] in self.all_ops]) == self.max_ops
        assert len([1 for v in stack if v is None]) == t_leaves

        # create leaves
        leaves = self._get_leaves(t_leaves, num_var, dup_var_prob, rng)
        rng.shuffle(leaves)

        # insert leaves into tree
        for pos in range(len(stack) - 1, -1, -1):
            if stack[pos] is None:
                stack[pos] = (leaves.pop(), 0)
        assert len(leaves) == 0
        return stack


def _prefix_to_infix(stack):
    if len(stack) == 0:
        raise RuntimeError("Empty prefix list.")
    t, num_children = stack[0]
    l1 = stack[1:]

    # Is a leaf
    if num_children == 0:
        if isinstance(t, str):
            return Var(t), l1
        else:
            return Const(t), l1

    args = []
    for _ in range(num_children):
        i1, l1 = _prefix_to_infix(l1)
        args.append(i1)
    return globals()[t](*args), l1


def prefix_stack_to_expression(stack):
    """
    Parse an prefix stack into expression.components.
    """
    expr, r = _prefix_to_infix(stack)
    return expr
