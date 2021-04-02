import angr
import pyvex
import networkx
from subprocess import Popen, PIPE, STDOUT

import logging
log = logging.getLogger('backward_slice.backward_slice_extraction')

from expression.components import C_TYPES, C_TYPES_INT, C_TYPES_FLOAT

#######################################
#
# Perform Backward Slicing on functions in a binary executable and extract the Vex AST of the return value.
#
#######################################

class BackwardVexExtractor:
    def __init__(self, elf_file_name):
        self.elf_file_name = elf_file_name
        self.proj = angr.Project(elf_file_name, load_options={'auto_load_libs': False, 'main_opts': {'base_addr': 0x0}})


    def _get_func_addr(self, func_name):
        for s in self.proj.loader.symbols:
            if func_name == s.name:
                return s.rebased_addr


    def _get_sorted_func_nodes(self, cfg, func_addr):
        func_nodes = []
        for node in cfg.model.nodes():
            if node.function_address == func_addr:
                func_nodes.append(node)
        func_nodes = sorted(func_nodes, key=lambda node: node.block.addr, reverse=False)
        return func_nodes


    def _locate_last_target_reg(self, func_nodes, target_reg):
        block_addr = None
        stmt_idx = None
        for node in func_nodes:
            irsb = node.block.vex
            for i, stmt in enumerate(irsb.statements):
                if isinstance(stmt, pyvex.stmt.Put):
                    reg_name = self.proj.arch.translate_register_name(stmt.offset)
                    if reg_name == target_reg:
                        block_addr = node.addr
                        stmt_idx = i
        return block_addr, stmt_idx


    def _get_stmt_graph_nodes(self, ddg, block_addr, stmt_idx):
        nodes = []
        for node in ddg.graph.nodes:
            if node.block_addr == block_addr and node.stmt_idx == stmt_idx:
                nodes.append(node)
        if len(nodes) == 0:
            raise angr.AngrDDGError("Could not find node corresponding to {}:{}".format(hex(block_addr), stmt_idx))
        return nodes


    def _get_bs_from_idx(self, cfg, cdg, ddg, 
                        block_nodes, bs_block_addr, bs_target_stmt_idx):
        block_addr_white_stmt_idx = {}
        block_addr_dep_stmt_idx = {}

        for node in block_nodes:
            block_addr_white_stmt_idx[node.addr] = []
            block_addr_dep_stmt_idx[node.addr] = []

        bs_targets = [(cfg.model.get_any_node(bs_block_addr), bs_target_stmt_idx)]
        try:
            bs = self.proj.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=bs_targets)
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

        tgt_ddg_nodes = self._get_stmt_graph_nodes(ddg, bs_block_addr, bs_target_stmt_idx)
        stack = tgt_ddg_nodes
        visited = set()
        while len(stack) > 0:
            node = stack.pop()
            node_block_addr = node.block_addr
            if node_block_addr != None:
                node_stmt_idx = node.stmt_idx
                block_addr_dep_stmt_idx[node_block_addr].append(node_stmt_idx)

            neighbors = ddg.graph.predecessors(node)
            for neighbor in neighbors:
                if not neighbor in visited:
                    stack.append(neighbor)
                    visited.add(neighbor)

        return block_addr_white_stmt_idx, block_addr_dep_stmt_idx


    def _collect_bs_vex(self, func_name, func_addr, func_nodes,
                            cfg, cdg, ddg, 
                            t_block_addr, stmt_idx):
        (block_addr_white_stmt_idx, 
         block_addr_dep_stmt_idx) = self._get_bs_from_idx(cfg, cdg, ddg, 
                                                     func_nodes, t_block_addr, stmt_idx)

        bs_vexs = []
        for node in func_nodes:
            block = node.block
            block_addr = block.addr

            whitelisted_statements = block_addr_white_stmt_idx[block_addr]
            dependent_statements = block_addr_dep_stmt_idx[block_addr]
            irsb = block.vex
            for i, stmt in enumerate(irsb.statements):
                if i in whitelisted_statements or i in dependent_statements:
                    bs_vexs.append(stmt)
        return bs_vexs


    def _get_reg_name(self, ret_type: str):
        if ret_type in C_TYPES_INT:
            sym_cc = self.proj.factory.cc_from_arg_kinds(fp_args=[], ret_fp=False)
        elif ret_type in C_TYPES_FLOAT:
            sym_cc = self.proj.factory.cc_from_arg_kinds(fp_args=[], ret_fp=True)
        else:
            raise Exception("Not handled return type")
        target_reg = sym_cc.return_val.reg_name
        return target_reg


    def extract_stmt_list(self, func_name: str, ret_type: str):
        # Collect source files

        # Collect function nodes
        func_addr = self._get_func_addr(func_name)
        cfg = self.proj.analyses.CFGEmulated(starts=[func_addr], 
                                        keep_state=True, 
                                        normalize=True, 
                                        state_add_options=angr.sim_options.refs, 
                                        call_depth=0)
        func_nodes = self._get_sorted_func_nodes(cfg, func_addr)

        # Get return register type
        target_reg = self._get_reg_name(ret_type)

        block_addr, stmt_idx = self._locate_last_target_reg(func_nodes, target_reg)

        # Generate CDG and DDG
        cdg = self.proj.analyses.CDG(cfg, start=func_addr)
        ddg = self.proj.analyses.DDG(cfg, start=func_addr)

        bs_vexs = self._collect_bs_vex(func_name, func_addr, func_nodes, 
                                            cfg, cdg, ddg, 
                                            block_addr, stmt_idx)
        return bs_vexs

    def extract_combined_vex(self, func_name: str, ret_type: str):
        target_reg = self._get_reg_name(ret_type)
        stmt_list = self.extract_stmt_list(func_name, ret_type)
        return combine_stmt_list(self.proj, stmt_list, target_reg)


#######################################
#
# combine_stmt_list related functions
#
#######################################
def _handle_assign_stmt_str(stmt_str):
    lhs, rhs = stmt_str.split(" = ")
    if "(" in lhs:
        lhs = lhs.split("(")[1].split(")")[0]
    rhs = rhs.replace("(", " ( ").replace(")", " ) ").replace(",", " , ")
    return lhs, rhs.split()

def _s32(value):
    return -(value & 0x80000000) | (value & 0x7fffffff)

def _proceed_stmt(value_dict, lhs, rhs):
    ret = []
    for ele in rhs:
        if ele.startswith("0x"):
            number = str(_s32(int(ele, 16)))
            ret.append(number)
        elif ele in value_dict:
            ret += value_dict[ele]
        else:
            ret.append(ele)
    value_dict[lhs] = ret

def combine_stmt_list(proj, stmt_list, target_reg):
    value_dict = {}
    for stmt in stmt_list:
        if isinstance(stmt, pyvex.stmt.Put):
            stmt_str = stmt.__str__(reg_name=proj.arch.translate_register_name(stmt.offset))
            lhs, rhs = _handle_assign_stmt_str(stmt_str)
        elif isinstance(stmt, pyvex.stmt.WrTmp): 
            if isinstance(stmt.data, pyvex.expr.Get):
                stmt_str = stmt.__str__(reg_name=proj.arch.translate_register_name(stmt.data.offset))
            else:
                stmt_str = stmt.__str__()
            lhs, rhs = _handle_assign_stmt_str(stmt_str)
        elif isinstance(stmt, pyvex.stmt.Store):
            stmt_str = stmt.__str__()
            lhs, rhs = _handle_assign_stmt_str(stmt_str)
        else:
            log.warning("Un-handled Vex type: %s" % type(stmt))
            log.warning(str(stmt))
            continue
        _proceed_stmt(value_dict, lhs, rhs)

    if target_reg not in value_dict:
        raise("Register not in stmt list, please report this error")
    return value_dict[target_reg]

