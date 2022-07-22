import argparse

# helper function
def balance(line):
    # returns new line, does not modify in place
    stack = []
    # TODO: extend to other types of brackets if needed
    try: 
        for i, c in enumerate(line):
            # print("for loop iteration", i, c)
            if c == '(':
                stack.append(c)
                # print("just pushed, current len of stack is: ", len(stack))
            elif c == ')':
                stack.pop()
                # print("just popped, current len of stack is: ", len(stack))
        balanced_line = line + (' )' * len(stack))
        return True, balanced_line, -1
    except IndexError:
        return False, line, i


parser = argparse.ArgumentParser(description='score mathematical equivalence using sympy')
parser.add_argument('-i', type=str, help="path to input file.", required=True)
parser.add_argument('-o', default='./balanced.txt', type=str, help="desired output location")

args = parser.parse_args()

with open(args.i, "r") as infile, open(args.o, "w") as outfile:
    for line in infile:
        success, result, index = balance(line.strip())
        # print(success, result, index)
        while not success:
            # try to remove extra closing parens
            # print("inside while loop")
            if all(c == ')' or c.isspace() for c in result[index:]):
                # print("if condition was true")
                result = result[0:index]
                success = True
            else:
                # try to add some opening parens
                success, result, index = balance("( " + result)
        # write result to output
        outfile.write(result + "\n")
print("balancing successful")
