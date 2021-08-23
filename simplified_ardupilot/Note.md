
## Patching angr to symbolic execute unsupported operations
```
## engines/vex/heavy/resilience.py:35

    def _check_unsupported_op(self, op, args):
        ty = pyvex.get_op_retty(op)
        if o.BYPASS_UNSUPPORTED_IROP not in self.state.options:
            return super()._check_unsupported_op(op, args)
        self.state.history.add_event('resilience', resilience_type='irop', op=op, message='unsupported IROp')
        # PATCH
        if ty == 'Ity_F32' or ty == 'Ity_F64':
            ret_type = claripy.ast.fp.FP
        else:
            ret_type = claripy.ast.bv.BV
        if len(args) == 1:
            calc_length = lambda x: claripy.fp.FSORT_DOUBLE.length
        elif len(args) == 2:
            calc_length = lambda x, y: claripy.fp.FSORT_DOUBLE.length
        elif len(args) == 3:
            calc_length = lambda x, y, z: claripy.fp.FSORT_DOUBLE.length
        elif len(args) == 0:
            calc_length = lambda : claripy.fp.FSORT_DOUBLE.length
        f = claripy.operations.op(op, [type(arg) for arg in args], ret_type,
                do_coerce=False, calc_length=calc_length)
        return f(*args)
        # PATCH
        return self.__make_default(ty, o.UNSUPPORTED_BYPASS_ZERO_DEFAULT not in self.state.options, 'unsupported_' + op)

```

```
## engines/vex/claripy/irop.py:287
class SimIROp:
# ........

        elif self._float and self._vector_zero:
            # /* --- lowest-lane-only scalar FP --- */
            f = getattr(claripy, 'fp' + self._generic_name, None)
            if f is not None:
                f = partial(f, claripy.fp.RM.default()) # always? really?

            f = f if f is not None else getattr(self, '_op_fgeneric_' + self._generic_name, None)

            # PATCH
            if f is None:
                if self._generic_name == "Sqrt":
                    f = claripy.operations.op("Sqrt", (claripy.ast.fp.FP),
                            claripy.ast.fp.FP, do_coerce=False, calc_length=lambda x:claripy.fp.FSORT_DOUBLE.length)
                else:
                    raise SimOperationError("no fp implementation found for operation {}".format(self._generic_name))
            # PATCH

            self._calculate = partial(self._auto_vectorize, f)
```

With angr being patched, `demo_init-mem.py` can be run in the root directory of this repo with:
```
»> with open("simplified_ardupilot/demo_init-mem.py", "r") as fd:
---   c = fd.read()
---   exec(c)
```

## Demo of backtracing
`demo_bt-callvar.py` demonstrate the usage of function written in `bt_func.py`. These scripts prints out all the addresses
called in `AP_SteerController.o`. If it's a concrete address, we simply print it. If it's a memory offset, the symbolic
value of the address is printed.
```
$ python bt_func.py
```
There are more experimental scripts in branch `dev/backward_slice` `backward_slice/` directory. These were used for capturing
values stored in pointers and arrays.
