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
    parser = argparse.ArgumentParser("Perform symbolic execution on the ardurover binary")
    parser.add_argument('binary', help='Path to ardurover binary')
    args = parser.parse_args()
    elf_path = args.binary
    see  = SymbolicExpressionExtractor(elf_path)
    millis_map = (0x6e2d82, ('millis', (), 'int'))
    #groundspeed_map = (0x45b9b6, ('groundspeed', (), 'int'))
    get_yaw_rate_earth_map = (0x447ba6, ('get_yaw_rate_earth', (), 'float'))
    degreesf_map = (0x449e46, ('degrees', ('float'), 'float'))
    constrain_value_line_map = (0x4b0dc6, ('constrain_value_line', ('float','float','float','int'), 'float'))
    #reset_filter_map = (0x684d42, ('reset_filter', ('int'), 'int'))
    #reset_ie_map = (0x7cb194, ('reset_ie', ('int'), 'int'))
    radiansf_map = (0x588afd, ('radiansf', ('float'), 'float'))
    #set_dt_map = (0x7caaae, ('set_dt', ('int'), 'int'))
    get_ff_map = (0x7cb12c, ('get_ff', ('int'), 'float'))
    update_all_map = (0x7cabf8, ('update_all', ('int', 'float','float','int'), 'float'))


    short_circuit_calls=dict((millis_map, get_yaw_rate_earth_map, degreesf_map, constrain_value_line_map, radiansf_map, get_ff_map, update_all_map))
    extracted_symexpr = see.extract('_ZN18AR_AttitudeControl21get_steering_out_rateEfbbf', ['this', 'desired_rate', 'motor_limit_left', 'motor_limit_right', 'dt'], ['int', 'float', 'int', 'int', 'float'], 'float', simplified=False, short_circuit_calls=short_circuit_calls)
    ast = extracted_symexpr.symex_expr
    print(ast)
    in_sym = extracted_symexpr.symex_to_infix()
    print("")
    print("".join(in_sym))






if __name__ == "__main__":
    main()
