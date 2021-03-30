#!/usr/bin/env python3

import os
import sys
import argparse

import angr
import pyvex
import networkx
from subprocess import Popen, PIPE, STDOUT

import term_color as tc


def main(argv):
    parser = argparse.ArgumentParser(description='Run a backwardslice test case')
    parser.add_argument('--elf_file_name', metavar='elf_file_name', type=str, required=True, help='the name of the executable file of the test case.')
    parser.add_argument('--block_addr', metavar='block_addr', type=str, default=None, help='the block address of the target statement of the backward slice')
    parser.add_argument('--stmt_idx', metavar='stmt_idx', type=int, default=None, help='the VEX statement index of the target statement of the backward slice')
    parser.add_argument('--func_name', metavar='func_name', type=str, required=True, help='the name of the function analyzing')

    args = parser.parse_args(argv[1:])
    elf_file_name = args.elf_file_name
    block_addr_str = args.block_addr
    stmt_idx = args.stmt_idx
    func_name = args.func_name

    srcline_addrs, addrs_srcline = _match_debug_line(func_name, elf_file_name)

    proj = angr.Project(elf_file_name, load_options={'auto_load_libs': False, 'main_opts': {'base_addr': 0x0}})

    # Sanity check
    func_addr = _get_func_addr(proj, func_name)
    if func_addr is None:
        print("Cannot find the address of function %s" % func_name)
        exit(1)
    cfg = proj.analyses.CFGEmulated(starts=[func_addr], 
                                    keep_state=True, 
                                    normalize=True, 
                                    state_add_options=angr.sim_options.refs, 
                                    call_depth=1)
    func_nodes = _get_func_nodes(cfg, func_addr)
    func_nodes_sorted = sorted(func_nodes, key=lambda node: node.block.addr, reverse=False)

    if block_addr_str != None:
        block_addr = int(block_addr_str, 0)
    else:
        _simple_print(proj, func_name, func_nodes_sorted, addrs_srcline)
        exit(0)

    block_node = cfg.model.get_any_node(addr=block_addr)
    if block_node is None:
        print("Cannot find the node of block address 0x%s" % hex(block_addr))
        exit(1)
    if stmt_idx >= len(block_node.block.vex.statements):
        print("Cannot find stmt idx %s of block address 0x%s" % (stmt_idx, hex(block_addr)))
        exit(1)

    cdg = proj.analyses.CDG(cfg, start=func_addr)
    ddg = proj.analyses.DDG(cfg, start=func_addr)

    abs_idx = 0
    block_abs_map = {}
    for node in func_nodes_sorted:
        irsb = node.block.vex
        size = len(irsb.statements)
        block_abs_map[node.addr] = abs_idx
        abs_idx += size

    generate_vex_and_bs(proj, func_name, func_addr, func_nodes_sorted, 
                        cfg, cdg, ddg, 
                        block_addr, stmt_idx, 
                        block_abs_map, addrs_srcline)


#####
def _match_debug_line(func_name, elf_file_name):
    cmd = "objdump -dl %s" % elf_file_name
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    ret, err = process.communicate()
    srcline_addrs = {}
    addrs_srcline = {}
    start_record = False
    src_line = None
    for line in ret.decode().splitlines():
        if line.startswith("%s():" % func_name):
            start_record = True
            continue
        if not start_record:
            continue
        if len(line) == 0:
            break
        if line.startswith("/"):
            file, line = line.split(":")
            src_line = (line, file)
            srcline_addrs[src_line] = set()
        else:
            line_no = int(line.strip().split(":", 1)[0], 16)
            addrs_srcline[line_no] = src_line
            srcline_addrs[src_line].add(line_no)

    return srcline_addrs, addrs_srcline


#####
def _simple_print(proj, func_name, func_nodes, addrs_srcline):
    print("FUNCTION: {}".format(func_name))
    for node in func_nodes:
        print()
        print()
        print("---------")
        block = node.block
        block_addr = block.addr
        block_exit_str = ""
        print(" BLOCK: 0x{:x} {}".format(block_addr, block_exit_str))

        cur_line = None
        for idx in range(block.instructions):
            addr = node.block.instruction_addrs[idx]
            line = addrs_srcline[addr]
            if cur_line is None or line != cur_line:
                cur_line = line
                print("\t%s:%s" % (line[1].split("/", -1)[-1], line[0]))
            inst_str ="\t    %s" % str(block.capstone.insns[idx])
            print(inst_str)

        print()
        irsb = block.vex
        cur_line = None
        print(" IRSB:")
        for i, stmt in enumerate(irsb.statements):
            stmt_label = "0x{:x} [{:03}]".format(block_addr, i)
            stmt_str = stmt.__str__()
            if isinstance(stmt, pyvex.stmt.Put):
                stmt_str = stmt.__str__(reg_name=proj.arch.translate_register_name(stmt.offset))
            elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
                stmt_str = stmt.__str__(reg_name=proj.arch.translate_register_name(stmt.data.offset))
            elif isinstance(stmt, pyvex.stmt.Exit):
                stmt_str = stmt.__str__(reg_name=proj.arch.translate_register_name(stmt.offsIP))
            else:
                stmt_str = stmt.__str__()
            stmt_color = stmt_str

            if isinstance(stmt, pyvex.stmt.IMark):
                addr = stmt.addr
                line = addrs_srcline[addr]
                if cur_line is None or line != cur_line:
                    cur_line = line
                    print("\t%s:%s" % (line[1].split("/", -1)[-1], line[0]))

            print("\t    {} : {}".format(stmt_label, stmt_color))



def _get_func_addr(proj, func_name):
    for s in proj.loader.symbols:
        if func_name == s.name:
            return s.rebased_addr


def _get_func_nodes(cfg, func_addr):
    func_nodes = []
    for node in cfg.model.nodes():
        if node.function_address == func_addr:
            func_nodes.append(node)
    return func_nodes


def _get_stmt_graph_nodes(ddg, block_addr, stmt_idx):
    nodes = []
    for node in ddg.graph.nodes:
        if node.block_addr == block_addr and node.stmt_idx == stmt_idx:
            nodes.append(node)
    if len(nodes) == 0:
        raise angr.AngrDDGError("Could not find node corresponding to {}:{}".format(hex(block_addr), stmt_idx))
    return nodes


def _get_bs_from_idx(proj, cfg, cdg, ddg, 
                    block_nodes, bs_block_addr, bs_target_stmt_idx, block_abs_map):
    block_addr_white_stmt_idx = {}
    block_addr_dep_stmt_idx = {}
    white_stmt_idx = []
    dep_stmt_idx = []

    for node in block_nodes:
        block_addr_white_stmt_idx[node.addr] = []
        block_addr_dep_stmt_idx[node.addr] = []

    bs_targets = [(cfg.model.get_any_node(bs_block_addr), bs_target_stmt_idx)]
    try:
        bs = proj.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=bs_targets)
    except:
        print(bs_targets)
        bs = None
    if bs is None:
        return [], [] 

    acfg = bs.annotated_cfg()
    for block_node in block_nodes:
        addr = block_node.addr
        stmts = acfg.get_whitelisted_statements(addr)
        block_addr_white_stmt_idx[addr] = stmts
        block_abs_idx = block_abs_map[addr]
        for stmt_idx in stmts:
            white_stmt_idx.append(stmt_idx + block_abs_idx)

    tgt_ddg_nodes = _get_stmt_graph_nodes(ddg, bs_block_addr, bs_target_stmt_idx)
    stack = tgt_ddg_nodes
    visited = set()
    while len(stack) > 0:
        node = stack.pop()
        node_block_addr = node.block_addr
        if node_block_addr != None:
            node_stmt_idx = node.stmt_idx
            dep_stmt_idx.append(node_stmt_idx + block_abs_map[node_block_addr])
            block_addr_dep_stmt_idx[node_block_addr].append(node_stmt_idx)

        neighbors = ddg.graph.predecessors(node)
        for neighbor in neighbors:
            if not neighbor in visited:
                stack.append(neighbor)
                visited.add(neighbor)

    return white_stmt_idx, dep_stmt_idx, block_addr_white_stmt_idx, block_addr_dep_stmt_idx


def generate_vex_and_bs(proj, func_name, func_addr, func_nodes,
                        cfg, cdg, ddg, 
                        t_block_addr, stmt_idx,
                        block_abs_map, addrs_srcline):
    (white_stmt_idx, 
     dep_stmt_idx, 
     block_addr_white_stmt_idx, 
     block_addr_dep_stmt_idx) = _get_bs_from_idx(proj, 
                                                 cfg, cdg, ddg, 
                                                 func_nodes, t_block_addr, stmt_idx, block_abs_map)

    # Finish handling, print out resutls
    print("FUNCTION: {}".format(func_name))
    for node in func_nodes:
        print()
        block = node.block
        block_addr = block.addr
        block_exit_str = ""
        print(" BLOCK: 0x{:x} {}".format(block_addr, block_exit_str))

        cur_line = None
        for idx in range(block.instructions):
            addr = node.block.instruction_addrs[idx]
            line = addrs_srcline[addr]
            if cur_line is None or line != cur_line:
                cur_line = line
                print("\t%s:%s" % (line[1].split("/", -1)[-1], line[0]))
            inst_str ="\t    %s" % str(block.capstone.insns[idx])
            print(inst_str)

        print()
        whitelisted_statements = block_addr_white_stmt_idx[block_addr]
        dependent_statements = block_addr_dep_stmt_idx[block_addr]
        irsb = block.vex
        cur_line = None
        print(" IRSB:")
        for i, stmt in enumerate(irsb.statements):
            stmt_label = "0x{:x}[{:03}]".format(block_addr, i)
            stmt_str = stmt.__str__()
            if isinstance(stmt, pyvex.stmt.Put):
                stmt_str = stmt.__str__(reg_name=proj.arch.translate_register_name(stmt.offset))
            elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
                stmt_str = stmt.__str__(reg_name=proj.arch.translate_register_name(stmt.data.offset))
            elif isinstance(stmt, pyvex.stmt.Exit):
                stmt_str = stmt.__str__(reg_name=proj.arch.translate_register_name(stmt.offsIP))
            else:
                stmt_str = stmt.__str__()
            stmt_color = stmt_str

            if isinstance(stmt, pyvex.stmt.IMark):
                addr = stmt.addr
                line = addrs_srcline[addr]
                if cur_line is None or line != cur_line:
                    cur_line = line
                    print("\t%s:%s" % (line[1].split("/", -1)[-1], line[0]))
            
            if i in whitelisted_statements and i in dependent_statements:
                stmt_color = tc.TC_RED + tc.TC_BACK_GREEN + str(stmt_str) + tc.TC_RESET
            elif i in whitelisted_statements:
                stmt_color = tc.TC_RED + str(stmt_str) + tc.TC_RESET
            elif i in dependent_statements:
                stmt_color = tc.TC_BACK_GREEN + str(stmt_str) + tc.TC_RESET
            if not (block_addr, i) == (t_block_addr, stmt_idx):
                print("\t    {} : {}".format(stmt_label, stmt_color))
            else:
                print("\t(t) {} : {}".format(stmt_label, stmt_color))



if __name__ == '__main__':
    main(sys.argv)
