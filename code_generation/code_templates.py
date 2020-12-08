
'''
A code template for wrapping an expression in a function in a C program.
The template has the following tags that need to be populated:
    f_sig_ret:   The return type of the wrapper function.
    f_sig_name:  The name of the wrapper function
    f_sig_args:  The arguments of the wrapper function's signature.
    f_expr:      The C representation of the signature to wrap in the code.
    argc_min:    The minimum number of command line arguments required.
    usage_msg:   A usage message to display after "usage: argv[0] "
    f_call_args: The arguments to pass the wrapper function.
'''
C_CODE_TEMPLATE = \
"""\
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

{f_sig_ret:} {f_sig_name:}({f_sig_args:}) {{
    return {f_expr:};
}}

int main(int argc, char *argv[]) {{

    if (argc < {argc_min:}) {{
        fprintf(stderr, "usage: %s {usage_msg:}\\n", argv[0]);
        return EXIT_FAILURE;
    }}
    printf("%d\\n", {f_sig_name:}({f_call_args}));
    return EXIT_SUCCESS;
}}\
"""
