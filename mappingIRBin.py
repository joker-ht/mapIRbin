import os,sys
import MySQLdb
import IR_CFG as icfg
import bin_CFG as bcfg
import IDA_RPC_client as ida
sys.path.append(r"/home/seclab/xujianhao/checkCF/tracing_kernel/scripts")
from my_addr2line import addr2line_with_db_cache
from mysql_config import read_config

real_f_path = os.path.realpath(__file__)
this_path = real_f_path[:real_f_path.rfind('/')]

def addr2line(addr, db_config, bin_name=None):
    host, db_user, db_password, db_name = read_config(db_config)
    db = MySQLdb.connect(host, db_user, db_password, db_name, charset='utf8', autocommit=True)
    cursor = db.cursor()
    res = addr2line_with_db_cache(addr, cursor, bin_name)
    db.close()
    return res
    # return status, file_name, func_name, line_no

class mapping(object):

    def __init__(self, inst_addr, db_config=None, bin_ida_server=None, bin_name=None):
        # can be initialized by an addr
        
        # default config
        if db_config is None:
            db_config = db_config = this_path + '/static_info.config.json'
        if bin_ida_server is None:
            bin_ida_server = "http://114.212.85.187:12345"
        if bin_name is None:
            bin_name = "~/xujianhao/checkCF/tracing_kernel/linux-5.7.0-rc5/vmlinux "

        status, self.file_name, _, _ = addr2line(inst_addr, db_config, bin_name)
        self.func_name = ida.get_func_name(inst_addr, bin_ida_server)
        # func_name is '' if not found in IDA, we make CFGs be empty then.
        
        self.IR_cfg  = icfg.IR_CFG(self.file_name, self.func_name, db_config)
        self.bin_cfg = bcfg.bin_CFG(self.file_name, self.func_name, inst_addr, bin_ida_server)


def test_call_fea(addr):
    map_obj = mapping(addr)
    print('#', hex(addr), map_obj.file_name, map_obj.func_name, ':')

    def parser_features(graph_obj):
        feature_statistic_dic = dict()
        # print(graph_obj.node_features_map)
        # key = feature, value = list(Node_id)
        for node in graph_obj.node_features_map:
            features = graph_obj.node_features_map[node]
            for fea in features:
                feature_statistic_dic.setdefault(fea,[]).append(node)
                
        return feature_statistic_dic

    def print_call_fea(feature_statistic_dic):
        for fea in feature_statistic_dic:
            if 'call' in fea:
                print(fea, ':', feature_statistic_dic[fea])     
    
    def cmp_call_fea(feature_statistic_dic1, feature_statistic_dic2):

        for fea in feature_statistic_dic1:
            if 'call' in fea:
                len1 = len(feature_statistic_dic1[fea])
                if fea in feature_statistic_dic2.keys():
                    len2 = len(feature_statistic_dic2[fea])
                    if len1 != len2:
                        print(fea, '%d:%d'%(len1, len2))
                        # print(feature_statistic_dic1[fea], feature_statistic_dic2[fea])
                else:
                    print(fea, '%d:0'%(len1))
                    # print(feature_statistic_dic1[fea])
        for fea in feature_statistic_dic2:
            if 'call' in fea:
                if fea not in feature_statistic_dic1.keys():
                    print(fea, '0:%d'%(len(feature_statistic_dic2[fea])))
                    # print(feature_statistic_dic2[fea])

    # print_call_fea(parser_features(map_obj.IR_cfg))
    # print('&')
    # print_call_fea(parser_features(map_obj.bin_cfg))
    # print('&')
    cmp_call_fea(parser_features(map_obj.IR_cfg), parser_features(map_obj.bin_cfg))

def test_cfg_len(addr):
    map_obj = mapping(addr)
    # print('#', hex(addr), map_obj.file_name, map_obj.func_name, ':')
    print(len(map_obj.IR_cfg.node_features_map), len(map_obj.bin_cfg.node_features_map))
   

if __name__ == "__main__":
    # with open( this_path+'/new_addr.txt', 'r') as f:
    #     addrs = f.readlines()
    # for addr in addrs:
    #     test_call_fea(int(addr,16))
    #     # test_cfg_len(int(addr,16))

    test_call_fea(0xffffffff81219144)
    # test_call_fea(0xffffffff811c25e9)