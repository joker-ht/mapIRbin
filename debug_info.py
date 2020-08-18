import os,sys
import MySQLdb
import mappingIRBin as mapping
import bin_CFG as bcfg
import IR_CFG as icfg
import IDA_RPC_client as ida
sys.path.append(r"/home/seclab/xujianhao/checkCF/tracing_kernel/scripts")
# from my_addr2line import addr2line_with_db_cache
from mysql_config import read_config

real_f_path = os.path.realpath(__file__)
this_path = real_f_path[:real_f_path.rfind('/')]
db_config = this_path + '/static_info.config.json'


def get_src_lines_of_IR_bb(file_name, label, db_config):
    host, db_user, db_password, db_name = read_config(db_config)
    db = MySQLdb.connect(host, db_user, db_password, db_name, charset='utf8', autocommit=True)
    db_cursor = db.cursor()

    get_debug_info_sql = "SELECT * FROM bb_range \
        WHERE bb_file = '%s' and bb_label = '%s'" % (file_name,label)
    try:
        db_cursor.execute(get_debug_info_sql)
        debug_info_list = db_cursor.fetchall()
    except:
        print("Error:", get_debug_info_sql)
        return []
    db.close()

    lines = []
    for bb_info in debug_info_list:
        if(bb_info[0] != bb_info[2]):
            print("!!! some inst of bb not in raw file ", bb_info[0], ", now in ", bb_info[2]) 
        # FIXIT: whether it is needed to consider these cross-file inline insts
        else:
            lines.append(bb_info[3])
    
    # lines_unduplicated = list(set(lines)).sort(key=lines.index)
    return lines
        
def get_src_lines_of_IR_func(file_name, func_name, db_config):
    host, db_user, db_password, db_name = read_config(db_config)
    db = MySQLdb.connect(host, db_user, db_password, db_name, charset='utf8', autocommit=True)
    db_cursor = db.cursor()

    get_debug_info_sql = "SELECT * FROM bb_range \
        WHERE bb_file = '%s' and bb_label like '%s\\%%%%'" % (file_name,func_name)
    try:
        db_cursor.execute(get_debug_info_sql)
        debug_info_list = db_cursor.fetchall()
    except:
        print("Error:", get_debug_info_sql)
        return []
    db.close()

    lines = []
    for bb_info in debug_info_list:
        if(bb_info[0] != bb_info[2]):
            print("!!! some inst not in raw file ", bb_info[0], ", now in ", bb_info[2]) 
        # FIXIT: whether it is needed to consider these cross-file inline insts
        else:
            lines.append(bb_info[3])
    
    # lines_unduplicated = list(set(lines)).sort(key=lines.index)
    return lines

def get_src_lines_of_bin_bb(addr, real_file_name, db_config, bin_ida_server=None, bin_name=None):
    insts = ida.get_bb_insts(addr, bin_ida_server)
    # print(insts)

    lines = []
    for inst in insts:
        status, file_name, func_name, line_no = mapping.addr2line(int(inst,16), db_config, bin_name)
        if status==-1 or func_name =='?':
            print(inst, 'is not addr2line-able')
            continue
        # FIXIT: whether it is needed to consider these cross-file inline insts
        if file_name == real_file_name:
            lines.append(line_no)

    # lines_unduplicated = list(set(lines)).sort(key=lines.index)
    return lines
        
def get_src_lines_of_bin_func(addr, real_file_name, db_config, bin_ida_server=None, bin_name=None):
    insts = ida.get_func_insts(addr, bin_ida_server)
    # print(insts)

    lines = []
    for inst in insts:
        status, file_name, func_name, line_no = mapping.addr2line(int(inst,16), db_config, bin_name)
        if status==-1 or func_name =='?':
            print(inst, 'is not addr2line-able')
            continue
        # FIXIT: whether it is needed to consider these cross-file inline insts
        if file_name == real_file_name:
            lines.append(line_no)

    # lines_unduplicated = list(set(lines)).sort(key=lines.index)
    return lines

def exclusive_line_of_ir_bb(file_name, func_name, db_config):
    # get debug info of this function
    host, db_user, db_password, db_name = read_config(db_config)
    db = MySQLdb.connect(host, db_user, db_password, db_name, charset='utf8', autocommit=True)
    db_cursor = db.cursor()
    # disallow inline insts in other files here, since their line is the number in another file.
    get_debug_info_sql = "SELECT * FROM bb_range \
        WHERE bb_file = '%s' and bb_label like '%s\\%%%%'" % (file_name,func_name)
    try:
        db_cursor.execute(get_debug_info_sql)
        debug_info_list = db_cursor.fetchall()
        # print(get_debug_info_sql)
    except:
        print("Error:", get_debug_info_sql)
        return []
    db.close()

    # get all the BBs a line can be in 
    line_label_map = {}
    for bb_info in debug_info_list:
        if(bb_info[0] != bb_info[2]):
            print("!!! some inst not in raw file ", bb_info[0], ", now in ", bb_info[2]) 
        # FIXIT: whether it is needed to consider these cross-file inline insts
        else:
            full_label = bb_info[1]
            label = full_label.split('%')[1]
            line = bb_info[3]
            line_label_map.setdefault(line,[]).append(label)
    
    # bb_2_exclusive_lines, the map of some BB and all its exclusive src-lines.
    bb_2_exclusive_lines = {}
    for line in line_label_map:
        if len(line_label_map[line])== 1:
            distinct_bb = line_label_map[line][0]
            bb_2_exclusive_lines.setdefault(distinct_bb,[]).append(line)
         
    return bb_2_exclusive_lines

#add 8.7
def get_src_lines_of_IR_bb1(file_name, func_name , label, db_config):
    # get debug info of this function
    host, db_user, db_password, db_name = read_config(db_config)
    db = MySQLdb.connect(host, db_user, db_password, db_name, charset='utf8', autocommit=True)
    db_cursor = db.cursor()
    # disallow inline insts in other files here, since their line is the number in another file.
    get_debug_info_sql = "SELECT * FROM bb_range \
        WHERE bb_file = '%s' and bb_label like '%s\\%%%%'" % (file_name,func_name)
    try:
        db_cursor.execute(get_debug_info_sql)
        debug_info_list = db_cursor.fetchall()
        # print(get_debug_info_sql)
    except:
        print("Error:", get_debug_info_sql)
        return []
    db.close()

    lines = []
    for bb_info in debug_info_list:
        if(bb_info[0] != bb_info[2]):
            print("!!! some inst of bb not in raw file ", bb_info[0], ", now in ", bb_info[2]) 
        # FIXIT: whether it is needed to consider these cross-file inline insts
        else:
            full_label = bb_info[1]
            label1 = full_label.split('%')[1]
            if label1 == label:
                lines.append(bb_info[3])
                
    # lines_unduplicated = list(set(lines)).sort(key=lines.index)
    return lines

def exclusive_line_of_bin_bb(file_name, func_name, block_insts, db_config):
    # block_insts is the set of all BB's first addr in this function
    line_bb_map = {}
    for bb_inst in block_insts:
        bb_insts = ida.get_bb_insts(int(bb_inst,16))
        status, ifile_name, ifunc_name, line_no = mapping.addr2line(int(bb_inst,16),db_config)
        # allow different ifunc_name here, their debug info cannbe a hint. cross-file inline insts are banned here
        if status==-1 or ifile_name!=file_name:
            continue
        line_bb_map.setdefault(line_no,[]).append(bb_inst)

    bb_2_exclusive_lines = {}
    for line in line_bb_map:
        if len(line_bb_map[line])==1:
            distinct_bb = line_bb_map[line][0]
            bb_2_exclusive_lines.setdefault(distinct_bb,[]).append(line)
    
    return bb_2_exclusive_lines

def howmany_distinct_IRbbs():
    with open( this_path+'/new_addr.txt', 'r') as f:
        addrs = f.readlines()
    
    executed_funcs = set()
    for addr in addrs:
        # map_obj = mapping.mapping(int(addr,16))
        func_name = ida.get_func_name(int(addr,16))
        if func_name in executed_funcs  or func_name == '':
            continue
        executed_funcs.add(func_name)

        _, file_name, _, _ = mapping.addr2line(int(addr,16), db_config, bin_name=None)
        IR_cfg  = icfg.IR_CFG(file_name, func_name, db_config)
        bb_2_exclusive_lines = exclusive_line_of_ir_bb(file_name, func_name, db_config)
        distinct_bb_count = len(bb_2_exclusive_lines)
        bb_count = len(IR_cfg.graph.nodes)
        
        if bb_count != 0:
            print(addr.strip(), distinct_bb_count, '/', bb_count, distinct_bb_count/bb_count)
        else:
            print(addr.strip(), distinct_bb_count, '/', bb_count, map_obj.func_name)
    
def howmany_distinct_bin_bbs():
    bin_ida_server = "http://114.212.81.134:12345"

    with open( this_path+'/new_addr.txt', 'r') as f:
        addrs = f.readlines()
    
    executed_funcs = set()
    for addr in addrs:
        func_name = ida.get_func_name(int(addr,16))
        if func_name in executed_funcs  or func_name == '':
            continue
        # FIXME: we get filename from addr2line, it maynot be the true filename because of inlining
        #   - NOTE : exclusive_line_of_bin_bb() use this filname to choose inst
        #   - It is fair when cmpared with IR, but if we change the way to get filename here, IR part should be updated either. 
        status, ifile_name, ifunc_name, _ = mapping.addr2line(int(addr,16), db_config, bin_name=None)
        # we allow insts in other functions here
        if status==-1 or ifunc_name=='?':
            continue
        executed_funcs.add(func_name)
        
        bin_cfg = bcfg.bin_CFG(ifile_name, func_name, int(addr,16), bin_ida_server)
        bb_2_exclusive_lines = exclusive_line_of_bin_bb(ifile_name, func_name, bin_cfg.graph.nodes, db_config)
        distinct_bb_count = len(bb_2_exclusive_lines)
        bb_count = len(bin_cfg.graph.nodes)
        if bb_count != 0:
            print(addr.strip(), distinct_bb_count, '/', bb_count, distinct_bb_count/bb_count)
        else:
            print(addr.strip(), distinct_bb_count, '/', bb_count, map_obj.func_name)

def cmp_distinct_bbs_in_f(file_name, func_name, bin_bb_insts, db_config):
# to map distinct_bbs of IR and binary in one function, return {ir_bb:bin_bbs[]}
    ir_distinct_bb_map = exclusive_line_of_ir_bb(file_name, func_name, db_config)
    bin_distinct_bb_map = exclusive_line_of_bin_bb(file_name, func_name, bin_bb_insts, db_config)

    mapped_IR_bin_BB = {}

    for ir_bb in ir_distinct_bb_map:
        ir_lines = ir_distinct_bb_map[ir_bb]
        ir_f = False      
        for bin_bb in bin_distinct_bb_map:
            bin_lines = bin_distinct_bb_map[bin_bb]
            shared_lines = set(ir_lines) & set(bin_lines)
            if shared_lines!=set():
                ir_f = True
                mapped_IR_bin_BB.setdefault(ir_bb,[]).append(bin_bb)
                # print('find shared exclusive lines in', func_name, ir_bb, bin_bb, shared_lines)
        
                # 1 ir_bb may map to more than 1 bin_bb, so donot break here
        
        if ir_f == False:
            # print('this ir_bb donot have a shared exclusive lines')
            pass
    # return the mapping result
    return mapped_IR_bin_BB

def cmp_distinct_bbs():
# using distinct_bbs of IR and binary to map,
# print the percentage of mapped IR BBs 

    with open(this_path+'/new_addr.txt', 'r') as f:
        addrs = f.readlines()
    executed_funcs = set()
    for addr in addrs:
        func_name = ida.get_func_name(int(addr,16))
        if func_name in executed_funcs or func_name == '':
            continue
        executed_funcs.add(func_name)

        cmp_obj = mapping.mapping(int(addr,16))
        mapped_IR_bin_BB = cmp_distinct_bbs_in_f(cmp_obj.file_name, cmp_obj.func_name, cmp_obj.bin_cfg.graph.nodes, db_config)
        mapped_IR_bb_count = len(mapped_IR_bin_BB)
        IR_bb_count = len(cmp_obj.IR_cfg.graph.nodes)
        print(addr.strip(), func_name, 'IR bb mapped:', mapped_IR_bb_count, '/', IR_bb_count)

def cmp_debuginfo_in_func():
    # cmp IR and binary's source_line in some function
    with open(this_path+'/new_addr.txt', 'r') as f:
        addrs = f.readlines()
    
    executed_funcs = set()
    for addr in addrs:
        func_name = ida.get_func_name(int(addr,16))
        if func_name in executed_funcs or func_name == '':
            continue
        executed_funcs.add(func_name)

        _, file_name, _, _ = mapping.addr2line(int(addr,16), db_config, bin_name=None)
        map_obj = mapping.mapping(int(addr,16))
        ir_func_lines = get_src_lines_of_IR_func(file_name,func_name,db_config)
        bin_func_lines = get_src_lines_of_bin_func(int(addr,16), file_name, db_config)
        ir_func_lineset = set(ir_func_lines)
        bin_func_lineset = set(bin_func_lines)

        print(len(ir_func_lineset), len(bin_func_lineset), len(ir_func_lineset & bin_func_lineset))
        # print(ir_func_lineset-bin_func_lineset)
        # print(',')
        # print(bin_func_lineset-ir_func_lineset)

#8.7 add
def line_of_ir_bb(file_name, func_name, db_config):
    # get debug info of this function
    host, db_user, db_password, db_name = read_config(db_config)
    db = MySQLdb.connect(host, db_user, db_password, db_name, charset='utf8', autocommit=True)
    db_cursor = db.cursor()
    # disallow inline insts in other files here, since their line is the number in another file.
    get_debug_info_sql = "SELECT * FROM bb_range \
        WHERE bb_file = '%s' and bb_label like '%s\\%%%%'" % (file_name,func_name)
    try:
        db_cursor.execute(get_debug_info_sql)
        debug_info_list = db_cursor.fetchall()
        # print(get_debug_info_sql)
    except:
        print("Error:", get_debug_info_sql)
        return []
    db.close()

    # get all the BBs a line can be in 
    line_label_map = {}
    for bb_info in debug_info_list:
        if(bb_info[0] != bb_info[2]):
            print("!!! some inst not in raw file ", bb_info[0], ", now in ", bb_info[2]) 
        # FIXIT: whether it is needed to consider these cross-file inline insts
        else:
            full_label = bb_info[1]
            label = full_label.split('%')[1]
            line = bb_info[3]
            line_label_map.setdefault(line,[]).append(label)
    
    # bb_2_exclusive_lines, the map of some BB and all its exclusive src-lines.
    bb_2_exclusive_lines = {}
    for line in line_label_map:
        if len(line_label_map[line])== 1:
            distinct_bb = line_label_map[line][0]
            bb_2_exclusive_lines.setdefault(distinct_bb,[]).append(line)
         
    return bb_2_exclusive_lines

def line_of_bin_bb(file_name, func_name, block_insts, db_config):
    # block_insts is the set of all BB's first addr in this function
    line_bb_map = {}
    for bb_inst in block_insts:
        bb_insts = ida.get_bb_insts(int(bb_inst,16))
        status, ifile_name, ifunc_name, line_no = mapping.addr2line(int(bb_inst,16),db_config)
        # allow different ifunc_name here, their debug info cannbe a hint. cross-file inline insts are banned here
        if status==-1 or ifile_name!=file_name:
            continue
        line_bb_map.setdefault(line_no,[]).append(bb_inst)

    bb_2_exclusive_lines = {}
    for line in line_bb_map:
        if len(line_bb_map[line])==1:
            distinct_bb = line_bb_map[line][0]
            bb_2_exclusive_lines.setdefault(distinct_bb,[]).append(line)
    
    return bb_2_exclusive_lines

if __name__ == "__main__":
    addr = 0xffffffff811cc210
    _, file_name, _, _ = mapping.addr2line(addr, db_config, bin_name=None)
    func_name = ida.get_func_name(addr)
    print(exclusive_line_of_ir_bb(file_name, func_name, db_config))
    print(get_src_lines_of_IR_bb1(file_name,func_name,'140',db_config))
    # cmp_debuginfo_in_func()
    print(get_src_lines_of_bin_bb(addr,file_name,db_config))
    # howmany_distinct_IsRbbs()
    # howmany_distinct_bin_bbs()
    # cmp_distinct_bbs()
    # cmp_debuginfo_in_func()
    