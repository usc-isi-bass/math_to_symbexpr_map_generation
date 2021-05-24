import angr
import argparse
import claripy
import logging
import os

logging.getLogger('angr').disabled = True
logging.getLogger('angr').propagate = False
logging.getLogger('cle').disabled = True
logging.getLogger('cle').propagate = False

from symbolic_execution.symbolic_expression_extraction import SymbolicExpressionExtractor

def main():
    parser = argparse.ArgumentParser("Perform symbolic execution on the arduplane binary")
    parser.add_argument('binary', help='Path to arduplane binary')
    args = parser.parse_args()
    elf_path = args.binary

    see  = SymbolicExpressionExtractor(elf_path)
    millis_map = (0x62e3f8, ('millis', (), 'int'))
    groundspeed_map = (0x45b9b6, ('groundspeed', (), 'int'))
    get_yaw_rate_earth_map = (0x449e46, ('get_yaw_rate_earth', (), 'float'))
    degreesf_map = (0x449e46, ('degrees', ('float'), 'float'))
    constrain_value_line_map = (0x4d95b9, ('constrain_value_line', ('float','float','float','int'), 'float'))
    radiansf_map = (0x5b09e1, ('radiansf', ('float'), 'float'))

    short_circuit_calls=dict((millis_map, groundspeed_map, get_yaw_rate_earth_map, degreesf_map, constrain_value_line_map, radiansf_map))
    extracted_symexpr = see.extract('_ZN18AP_SteerController21get_steering_out_rateEf', ['this', 'desired_rate'], ['int', 'float'], 'int', simplified=False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    print(ast)
    in_sym = extracted_symexpr.symex_to_infix()
    print("".join(in_sym))






if __name__ == "__main__":
    main()
