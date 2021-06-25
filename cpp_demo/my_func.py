
# TODO: just copy from the other part, fix it
def symstate_init_reg_offset(state, reg_name, offset):
    if reg_name is None:
        return
    if reg_name == "rsp":
        log.debug("Skip rsp initialization")
        return
    elif reg_name == "rsi":
        reg = state.regs.rsi
    elif reg_name == "fs":
        reg = state.regs.rsi
    elif reg_name == "rdi":
        reg = state.regs.rdi
    elif reg_name == "rdx":
        reg = state.regs.rdx
    else:
        log.warning("Register not in symstate_init: %s" % reg_name)
        return
    init_mem = str(state.mem[reg+offset].uint64_t)
    name = init_mem.split(" at ", 1)[1][:-1].replace(" ", "_")
    # TODO: What type is each offset? Currently set to FPS
    state.mem[reg+offset].uint64_t = claripy.FPS(name, claripy.fp.FSORT_DOUBLE, explicit_name=True)


def symstate_get_reg_offset(state, reg_name, offset):
    if reg_name == "rsi":
        reg = state.regs.rsi
    elif reg_name == "rdi":
        reg = state.regs.rdi
    elif reg_name == "rdx":
        reg = state.regs.rdx
    else:
        log.warning("Register not in symstate_get_reg: %s" % reg_name)
        return
    init_mem = str(state.mem[reg+offset].uint64_t)
    name = init_mem.split(" at ", 1)[1][:-1].replace(" ", "_")
    return name, state.mem[reg + offset].uint64_t.resolved


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


def find_load_store_locations(proj, state, block):
    stmt_addr_list = get_block_stmt_addr(block)
    load_addrs, last_store, last_store_addr = get_mem_addr(proj, stmt_addr_list)
    load_locations = []
    for l, addr in load_addrs:
        print(l)
        # TODO: init mem directly
        reg, offset = parse_reg_offset(l)
        if offset is None:
            continue
        load_locations.append((reg, offset, addr))
    reg, offset = parse_reg_offset(last_store)
    store_locations = [(reg, offset, last_store_addr)]
    return load_locations, store_locations


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
        print("Load %s" % rhs)
        if rhs.startswith("0x"):
            location = str(_s32(int(rhs, 16)))
        else:
            location = "".join(e for e in tmpvar_dict[rhs])
        if location not in memory_dict:
            memory_dict[location] = ["*(%s)" % location]
        if (location, addr) not in load_addrs:
            load_addrs.add((location, addr))
        return memory_dict[location]
    # Else
    if isinstance(rhs_stmt, pyvex.expr.Get):
        stmt_str = rhs_stmt.__str__(reg_name=proj.arch.translate_register_name(rhs_stmt.offset))
        rhs = str(stmt_str).split("(",1)[1].split(")", 1)[0]
        print("Get %s" % rhs)
        if rhs not in tmpvar_dict:
            value = "i_%s" % rhs
            tmpvar_dict[rhs] = [value]
            return [value]
    else:
        stmt_str = rhs_stmt.__str__()
        rhs = str(stmt_str).replace("(", " ( ").replace(")", " ) ").replace(",", " , ")
        print("Oth %s" % rhs)
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

def get_mem_addr(proj, stmt_addr_list):
    tmpvar_dict = {}
    memory_dict = {}
    load_addrs = set()
    store_addrs = set()
    cur_line = None
    last_store_addr = None
    for (stmt, addr) in stmt_addr_list:
        if isinstance(stmt, pyvex.stmt.Exit):
            continue
        print("")
        print(stmt)
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
            last_store_addr = addr
        else:
            log.warning("Un-handled Vex type: %s" % type(stmt))
            log.warning(str(stmt))
            continue
    return load_addrs, location, addr
