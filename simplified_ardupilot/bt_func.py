import pyvex

def get_jump_call_location(proj, block):
    jump_var = str(block.vex.next)
    stmt_addr_list = get_block_stmt_addr(block)
    load_addr = _get_jump_var_content(proj, stmt_addr_list, jump_var)
    return load_addr


# TODO: is this the right way of patching own symbol?
# Where angr fill out memory (?)
# angr/state_plugins/light_registers.py: _fill
def get_safe_memory_addr(proj):
    last_addr = 0
    for symbol in proj.loader.symbols:
        addr = symbol.rebased_addr
        if last_addr < addr:
            last_addr = addr
    return last_addr


def get_block_stmt_addr(block):
    bs_vex_addrs = []
    irsb = block.vex
    for i, stmt in enumerate(irsb.statements):
        if isinstance(stmt, pyvex.stmt.IMark):
            addr = stmt.addr
        elif isinstance(stmt, pyvex.stmt.AbiHint):
            continue
        else:
            bs_vex_addrs.append((stmt, addr))
    return bs_vex_addrs

def _s32(value):
    return -(value & 0x80000000) | (value & 0x7fffffff)


def parse_reg_offset(location):
    if location.startswith("Add64") or location.startswith("Sub64"):
        op, rest = location[:-1].split("(", 1)
        lhs, rhs = rest.rsplit(",", 1)
        # Specially handle FS register
        if rhs == "i_fs":
            base = "fs"
            offset = int(lhs)
            return base, offset
        base, offset = parse_reg_offset(lhs)
        if op == "Add64":
            offset += int(rhs)
        else:
            offset -= int(rhs)
        return base, offset
    else:
        if location.startswith("i_"):
            return location.replace("i_", ""), 0
        else:
            return None, int(location)


def match_debug_line(func_name, elf_file_name):
    cmd = "objdump -dl %s" % elf_file_name
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    ret, err = process.communicate()
    addrs_srcline = {}
    srcline_contents = {}
    start_record = False
    src_line = None
    src_file = None
    for line in ret.decode().splitlines():
        if line.lstrip("; ").startswith("%s():" % func_name):
            start_record = True
            continue
        if not start_record:
            continue
        if len(line) == 0:
            break
        if line.lstrip("; ").startswith("/"):
            file, line = line.lstrip("; ").split()[0].split(":")
            src_file = file
            src_line = (line, file)
            line_no = int(line)
            srcline_contents[line_no] = tc.TC_BLUE + linecache.getline(file, line_no).strip() + tc.TC_RESET
        else:
            line_no = int(line.strip().split(":", 1)[0], 16)
            addrs_srcline[line_no] = src_line
    return srcline_contents, addrs_srcline

def _proceed_rhs(proj, tmpvar_dict, memory_dict, rhs_stmt, load_addrs, addr):
    # Load the value or init mem
    if isinstance(rhs_stmt, pyvex.expr.Load):
        rhs = str(rhs_stmt).split("(",1)[1].split(")", 1)[0]
        if rhs.startswith("0x"):
            location = str(_s32(int(rhs, 16)))
        else:
            location = "".join(e for e in tmpvar_dict[rhs])
        if location not in memory_dict:
            memory_dict[location] = ["*%s" % location]
        if (location, addr) not in load_addrs:
            load_addrs.add((location, addr))
        return memory_dict[location]
    # Else
    if isinstance(rhs_stmt, pyvex.expr.Get):
        stmt_str = rhs_stmt.__str__(reg_name=proj.arch.translate_register_name(rhs_stmt.offset))
        rhs = str(stmt_str).split("(",1)[1].split(")", 1)[0]
        if rhs not in tmpvar_dict:
            value = "i_%s" % rhs
            tmpvar_dict[rhs] = [value]
            return [value]
    else:
        stmt_str = rhs_stmt.__str__()
        rhs = str(stmt_str).replace("(", " ( ").replace(")", " ) ").replace(",", " , ")
    ret = []
    for ele in rhs.split():
        if ele.startswith("0x"):
            number = str(_s32(int(ele, 16)))
            ret.append(number)
        elif ele in tmpvar_dict:
            ret += tmpvar_dict[ele]
        else:
            ret.append(ele)
    return ret

def _proceed_ST_stmt(tmpvar_dict, memory_dict, lhs, rhs, store_addrs, addr):
    ret = []
    for ele in rhs:
        if ele.startswith("0x"):
            number = str(_s32(int(ele, 16)))
            ret.append(number)
        elif ele in tmpvar_dict:
            ret += tmpvar_dict[ele]
        else:
            ret.append(ele)
    location = "".join(e for e in tmpvar_dict[lhs])
    memory_dict[location] = ret
    store_addrs.add((location, addr))
    return location


def _get_jump_var_content(proj, stmt_addr_list, jump_var):
    tmpvar_dict = {}
    memory_dict = {}
    load_addrs = set()
    store_addrs = set()
    cur_line = None
    for (stmt, addr) in stmt_addr_list:
        if isinstance(stmt, pyvex.stmt.Exit):
            continue
        rhs = _proceed_rhs(proj, tmpvar_dict, memory_dict, stmt.data, load_addrs, addr)
        if isinstance(stmt, pyvex.stmt.Put):
            stmt_str = stmt.__str__(reg_name=proj.arch.translate_register_name(stmt.offset))
            lhs = stmt_str.split(" = ")[0].split("(",1)[1].split(")", 1)[0]
            tmpvar_dict[lhs] = rhs
        elif isinstance(stmt, pyvex.stmt.WrTmp):
            stmt_str = stmt.__str__()
            lhs = stmt_str.split(" = ")[0]
            tmpvar_dict[lhs] = rhs
        elif isinstance(stmt, pyvex.stmt.Store):
            lhs = next(stmt.expressions)
            location = _proceed_ST_stmt(tmpvar_dict, memory_dict, str(lhs), rhs, store_addrs, addr)
        else:
            log.warning("Un-handled Vex type: %s" % type(stmt))
            log.warning(str(stmt))
            continue
        if lhs == jump_var:
            return rhs
    return None
