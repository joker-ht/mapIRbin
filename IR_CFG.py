import os,sys
import MySQLdb
import json
sys.path.append(r"/home/seclab/xujianhao/checkCF/tracing_kernel/scripts")
import IR2graph
from mysql_config import read_config
from getIRinfo import get_IR_info

real_f_path = os.path.realpath(__file__)
this_path = real_f_path[:real_f_path.rfind('/')]

def build_IR_cfg(file_name, func_name, db_config):
    host, db_user, db_password, db_name = read_config(db_config)
    db = MySQLdb.connect(host, db_user, db_password, db_name, charset='utf8', autocommit=True)
    cursor = db.cursor()

    edges = IR2graph.get_edges_in_file_from_db(cursor, file_name)
    edges = IR2graph.filter_edges_by_func(edges, func_name)

    CFG = IR2graph.build_graph_from_edges(edges)
    db.close()
    return CFG

def get_IR_features(c_file_name, func_name):
    fea_of_cfile = get_IR_info(c_file_name)
    if fea_of_cfile is None:
        return
    
    # for given function in this file, go get its features
    feas = dict()
    for bb_info in fea_of_cfile:
        bb_id = bb_info["id"]
        bb_func, bb_label = bb_id.split('%')
        # FIXIT: Now we only consider 'call function'
        bb_call = bb_info["called function"]
        bb_cmp2reg = bb_info['cmp']
        bb_imm = bb_info['immediate']
        bb_select = bb_info['select instruction']
        bb_test = bb_info["cmp and"]
        if bb_func == func_name:
            feas[bb_label] = []
            for calledf in bb_call:
                if 'lifetime' in calledf:
                    continue  
                if 'memset' in calledf:
                    calledf = 'memset'
                feas[bb_label].append('call ' + calledf)
            for cmp2reg in bb_cmp2reg:
                if cmp2reg == 'yes':
                    feas[bb_label].append('cmp 2 reg')
                if cmp2reg == 'null':
                    feas[bb_label].append('cmp 0')
                # if cmp2reg and cmp2reg != 'yes':
                #     feas[bb_label].append('cmp ' + cmp2reg)
            imme = []
            if not bb_test:
                imme = bb_imm
            else:
                for test in bb_test:
                    if 'and' in test:
                        feas[bb_label].append('test ' + test.split('_')[0])
                immdict = {}
                for imm in bb_imm:
                    immdict.setdefault(imm,[]).append(imm)
                for memu in bb_test:
                    if 'cmp' in memu:
                        del immdict[memu][0]
                for value in immdict.values():
                    imme.extend(value)
            for imm in imme:
                value = imm.split('_')[0]
                if 'cmp' in imm:
                    feas[bb_label].append('cmp ' + value)
                    continue
                if 'shr' in imm:
                    feas[bb_label].append('shr ' + value)
                    continue
                if 'shl' in imm:
                    feas[bb_label].append('shl ' + value)
                    continue
                if 'and' in imm:
                    feas[bb_label].append('and ' + value)
                    continue
                if 'add' in imm:
                    feas[bb_label].append('add ' + value)
                    continue
                if 'or' in imm:
                    feas[bb_label].append('or ' + value)
                    continue
                if 'switch' in imm:
                    feas[bb_label].append('cmp ' + value)
            





            for sele in bb_select:
                if sele == 'yes':
                    feas[bb_label].append('cmov')
    return feas


class IR_CFG(object):
    def __init__(self, file_name, func_name, db_config=None):
        if db_config is None:
            db_config = this_path + '/static_info.config.json'
        self.file_name = file_name
        self.func_name = func_name
        self.graph = build_IR_cfg(file_name, func_name, db_config)
        self.node_features_map = get_IR_features(file_name, func_name)

if __name__ == "__main__":
    filename = '/home/seclab/xujianhao/linux/mm/mmap.c'
    funcname = 'do_mmap'
    db_config = this_path + '/static_info.config.json'

    ir_cfg = IR_CFG(filename, funcname, db_config)
    for node in ir_cfg.node_features_map.items():
        print(node)
    # for node in ir_cfg.graph.nodes:
    #     print(node)
    # IR2graph.draw_graph(ir_cfg.graph, funcname)
