import argparse

def prefix_to_infix(expr):
    stack = []

    tokens = expr.split()
    # read prefix in reverse order
    for tok in tokens[::-1]:
        if not isOperator(tok):
            # symbol is operand
            stack.append(tok)
        else:
            # symbol is operator
            str = "( " + stack.pop() + " " + tok + " " + stack.pop() + " )"
            stack.append(str)
            
    return stack.pop()
 
def isOperator(c):
    if c == "*" or c == "+" or c == "-" or c == "/" or c == "^" or c == "(" or c == ")":
        return True
    else:
        return False

parser = argparse.ArgumentParser(description='convert prefix to infix for eval')
parser.add_argument('--prefix', type=str, help="path to prefix expressions")

args = parser.parse_args()

with open(args.prefix) as prefix, open(args.prefix + ".infix", 'w') as infix:
    for num, line in enumerate(prefix):
        # convert to infix
        try:
            line_infix = prefix_to_infix(line)
            # write to file
            infix.write(line_infix + "\n")
        except:
            print(num)
