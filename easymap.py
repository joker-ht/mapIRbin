import os,sys
import mappingIRBin
import json
import re
import IR_CFG as icfg
import bin_CFG as bcfg
import networkx as nx
import IDA_RPC_client as ida
import mappingIRBin as mapbb
import debug_info as dbgif
# sys.path.append(r"/home/seclab/xujianhao/checkCF/tracing_kernel/scripts")

real_f_path = os.path.realpath(__file__)
this_path = real_f_path[:real_f_path.rfind('/')]
db_config = this_path + '/static_info.config.json'

#if one fea in BB1 is also in  
def map_two_BB(IR_BB_Fea,bin_BB_Fea):
    map_fea = []
    if IR_BB_Fea and bin_BB_Fea:
        map_fea = list(set(IR_BB_Fea)&set(bin_BB_Fea))

    if map_fea:
        return map_fea
    else:
        return False


# def map_edge(from_bb,to)

class easymap(mapbb.mapping):
    def __init__(self, inst_addr, db_config = None, bin_ida_server = None, bin_name = None):
        # # can be initialized by an addr
        
        # # default config
        # if db_config is None:
        #     db_config = db_config = this_path + '/static_info.config.json'
        # if bin_ida_server is None:
        #     bin_ida_server = "http://114.212.81.134:12345"
        # if bin_name is None:
        #     bin_name = "~/xujianhao/checkCF/tracing_kernel/linux-5.7.0-rc5/vmlinux "

        # status, self.file_name, _, _ = addr2line(inst_addr, db_config, bin_name)
        # self.func_name = ida.get_func_name(inst_addr, bin_ida_server)
        # # func_name is '' if not found in IDA, we make CFGs be empty then.
        
        # self.IR_cfg  = icfg.IR_CFG(self.file_name, self.func_name, db_config)
        # self.bin_cfg = bcfg.bin_CFG(self.file_name, self.func_name, inst_addr, bin_ida_server)
        super().__init__(inst_addr, db_config, bin_ida_server, bin_name)
        self.IR_graphwithfea = add_fea_to_graph(self.IR_cfg.graph,self.IR_cfg.node_features_map)
        self.bin_graphwithfea = add_fea_to_graph(self.bin_cfg.graph,self.bin_cfg.node_features_map)

count = 0
def add_fea_to_graph(G,feadic):
    for node in G.nodes:
        # print(node)
        G.nodes[node]['fea'] = feadic.setdefault(node,[])
        G.nodes[node]['label'] = node + '\n' + str(G.nodes[node]['fea'])
    return G

def fea_in_list(fea,fealist):
    if fealist:
        for node in fealist:
            if fea in node:
                return 1
    return 0

def map_with_dbgif(filename , funcname , label , addr, db_config):
    IRline = dbgif.get_src_lines_of_IR_bb1(filename,funcname,label,db_config)
    binline = dbgif.get_src_lines_of_bin_bb(addr,filename,db_config)
    cross = list(set(IRline)&set(binline))
    if cross:
        return 1

def test(addr):
   
    testmap = easymap(addr)
    # for node in testmap.IR_graphwithfea.nodes:
    #     print (node,testmap.IR_graphwithfea.nodes[node]['fea'])
    # print ('\n')
    # for node in testmap.bin_graphwithfea.nodes:
    #     print (node,testmap.bin_graphwithfea.nodes[node]['fea'])
    # print(testmap.IR_cfg.graph.edges)
    _, file_name, _, _ = mapbb.addr2line(addr, db_config, bin_name=None)
    filename = file_name
    funcname = testmap.func_name
    def add_IR_fea():
        testmap.IR_graphwithfea.nodes['106']['fea'] = ['cmp 4']
        testmap.IR_graphwithfea.nodes['108']['fea'] = ['test 16']
        testmap.IR_graphwithfea.nodes['116']['fea'] = ['and 7','and 10496','shl 4','and 8388608','test 8192']
        testmap.IR_graphwithfea.nodes['112']['fea'] = ['call __execute_only_pkey','cmov']
        testmap.IR_graphwithfea.nodes['135']['fea'] = ['call can_do_mlock']
        testmap.IR_graphwithfea.nodes['137']['fea'] = ['test 8192']
        testmap.IR_graphwithfea.nodes['140']['fea'] = ['shr 12','cmp 2 reg']
        testmap.IR_graphwithfea.nodes['152']['fea'] = ['test0']
        testmap.IR_graphwithfea.nodes['14']['fea'] = ['test 1']
        testmap.IR_graphwithfea.nodes['29']['fea'] = ['shr 16','and 16']
        testmap.IR_graphwithfea.nodes['154']['fea'] = ['and -4096','cmp -32768','cmp 24576','cmp -16384']
        testmap.IR_graphwithfea.nodes['264']['fea'] = ['cmp 1','cmp 2']
        testmap.IR_graphwithfea.nodes['160']['fea'] = ['shr 13','and 1','add -1']
        testmap.IR_graphwithfea.nodes['167']['fea'] = ['test0','cmp 2 reg']
        testmap.IR_graphwithfea.nodes['172']['fea'] = ['shr 12']
        testmap.IR_graphwithfea.nodes['22']['fea'] = ['test 0']
        testmap.IR_graphwithfea.nodes['176']['fea'] = ['and 15','cmp 1','cmp 3','cmp 2']
        testmap.IR_graphwithfea.nodes['186']['fea'] = ['and 2080897395']
        testmap.IR_graphwithfea.nodes['241']['fea'] = ['test 1']
        testmap.IR_graphwithfea.nodes['193']['fea'] = ['test 2']
        testmap.IR_graphwithfea.nodes['196']['fea'] = ['test 2']
        testmap.IR_graphwithfea.nodes['210']['fea'] = ['test 4']
        testmap.IR_graphwithfea.nodes['215']['fea'] = ['test 2']
        testmap.IR_graphwithfea.nodes['220']['fea'] = ['and 64','cmp 0','and 1032','cmp 1024']
        testmap.IR_graphwithfea.nodes['27']['fea'] = ['or 4']
        testmap.IR_graphwithfea.nodes['233']['fea'] = ['or 248','cmov']
        testmap.IR_graphwithfea.nodes['250']['fea'] = ['test 4']
        testmap.IR_graphwithfea.nodes['255']['fea'] =  ['cmp 0']
        testmap.IR_graphwithfea.nodes['253']['fea'] = ['and -65']
        testmap.IR_graphwithfea.nodes['261']['fea'] = ['test 256']
        testmap.IR_graphwithfea.nodes['266']['fea'] = ['test 256']
        testmap.IR_graphwithfea.nodes['271']['fea'] = ['shr 12']
        testmap.IR_graphwithfea.nodes['269']['fea'] = ['or 248']
        testmap.IR_graphwithfea.nodes['279']['fea'] = ['or 2097152']
        testmap.IR_graphwithfea.nodes['291']['fea'] = ['call mmap_region','cmp -4096']
        testmap.IR_graphwithfea.nodes['36']['fea'] = ['and -4096']
        testmap.IR_graphwithfea.nodes['295']['fea'] = ['and 98304','cmp 32768']
        testmap.IR_graphwithfea.nodes['42']['fea'] = ['add 4095','and -4096']
        testmap.IR_graphwithfea.nodes['50']['fea'] = ['shr 12']
        testmap.IR_graphwithfea.nodes['62']['fea'] = ['test 1048576']
        testmap.IR_graphwithfea.nodes['68']['fea'] = ['test0']
        testmap.IR_graphwithfea.nodes['89']['fea'] = ['test0']
        testmap.IR_graphwithfea.nodes['96']['fea'] = ['test0']

        testmap.IR_graphwithfea.nodes['9']['fea'] = ['cmp 2 reg', 'cmp 0']
        testmap.IR_graphwithfea.nodes['85']['fea'] = []
        testmap.IR_graphwithfea.nodes['87']['fea'] = []
        testmap.IR_graphwithfea.nodes['72']['fea'] = ['cmp 2 reg']
        testmap.IR_graphwithfea.nodes['59']['fea'] = ['call get_unmapped_area', 'cmp 2 reg', 'cmp -4096']
        testmap.IR_graphwithfea.nodes['54']['fea'] = ['cmp 2 reg']
        testmap.IR_graphwithfea.nodes['45']['fea'] = ['cmp 2 reg', 'cmp 0',  'add 4095', 'and-4096']
        testmap.IR_graphwithfea.nodes['284']['fea'] = ['cmp 2 reg']
        testmap.IR_graphwithfea.nodes['273']['fea'] = ['cmp 2 reg', 'cmp 0','test 16384']
        testmap.IR_graphwithfea.nodes['247']['fea'] = ['call path_noexec']
        testmap.IR_graphwithfea.nodes['230']['fea'] = ['call locks_mandatory_locked', 'cmp 2 reg', 'cmp 0']
        testmap.IR_graphwithfea.nodes['24']['fea'] = ['call path_noexec']
        testmap.IR_graphwithfea.nodes['201']['fea'] = ['cmp 2 reg', 'cmp 0']
        testmap.IR_graphwithfea.nodes['188']['fea'] = ['cmp 2 reg', 'cmp 0']
        testmap.IR_graphwithfea.nodes['183']['fea'] = []
        testmap.IR_graphwithfea.nodes['17']['fea'] = ['cmp 2 reg', 'cmp 0']
        testmap.IR_graphwithfea.nodes['302']['fea'] = []
        testmap.IR_graphwithfea.nodes['100']['fea'] = ['cmp 2 reg']
        
        # for node in testmap.IR_graphwithfea.nodes:
        #     print (node,testmap.IR_graphwithfea.nodes[node]['fea'])
    # add_IR_fea()

    #imm fea in bin is hex,let's change it to dec
    def change_hex_to_dec():
        for node in testmap.bin_graphwithfea.nodes:
                if testmap.bin_graphwithfea.nodes[node]['fea']:
                    for feat in testmap.bin_graphwithfea.nodes[node]['fea']:
                        if '0x' in feat or '2900' in feat:
                            immfea = feat.split('L')[0]
                            memu = feat.split(' ')[0]
                            value = int(immfea.split(' ')[1],16)
                            if 'ffffffff' in feat:
                                value = int(immfea.split(' ')[1],16) - int('0xffffffffffffffff',16) - 1
                            
                            newfea = memu + ' ' + str(value)
                            # print (newfea)
                            testmap.bin_graphwithfea.nodes[node]['fea'].remove(feat)
                            testmap.bin_graphwithfea.nodes[node]['fea'].insert(0,newfea)
                        if feat == 'test0':
                            testmap.bin_graphwithfea.nodes[node]['fea'].remove(feat)
                            testmap.bin_graphwithfea.nodes[node]['fea'].insert(0,'cmp 0')
                    # print (testmap.bin_graphwithfea.nodes[node]['fea'])
                    
    change_hex_to_dec()


    IR_edgewith_fea = {}
    bin_edgewith_fea = {}


    def add_fea_to_edge():
        for node in testmap.IR_graphwithfea.edges:
            edgefea = []
            IR_edgewith_fea[node] = []
            edgefea.append(testmap.IR_graphwithfea.nodes[node[0]]['fea'])
            edgefea.append(testmap.IR_graphwithfea.nodes[node[1]]['fea'])
            IR_edgewith_fea[node] = edgefea
        for node in testmap.bin_graphwithfea.edges:
            edgefea = []
            bin_edgewith_fea[node] = []
            edgefea.append(testmap.bin_graphwithfea.nodes[node[0]]['fea'])
            edgefea.append(testmap.bin_graphwithfea.nodes[node[1]]['fea'])
            bin_edgewith_fea[node] = edgefea
    add_fea_to_edge()
    # print (IR_edgewith_fea)
    # print (bin_edgewith_fea)
    # add_IR_fea()
    # print(testmap.IR_cfg.node_features_map)

    mapped_edge = []
    maooed_edge1 = []
    cormap = []
    correctmap = []
    mapped_IRnode = {}
    mapped_binnode = {}

    def cmp_edgewithfea():
        
        for key1,value1 in IR_edgewith_fea.items():
            for key2,value2 in bin_edgewith_fea.items():
                #now we consider the situation when from and to bb all have fea
                if (value1[0] and value2[0]) and (value1[1] and value2[1]):
                    if map_two_BB(value1[0],value2[0]) and map_two_BB(value1[1],value2[1]):
                        mapped_edge.append([key1,key2])
                # consider when from bb have fea but to not
                # elif value1[0] and value2[0]:
                #     if map_two_BB(value1[0],value2[0]):
                #         mapped_edge.append([key1,key2])
                # elif value1[1] and value2[1]:
                #     if map_two_BB(value1[1],value2[1]):
                #         mapped_edge.append([key1,key2])

        #check if the IRedge map multiple binedges
        dict1 = {}
        for node in mapped_edge:
            dict1.setdefault(node[1],[]).append(node[0])
        #[IRedge,binedge]

        for key,value in dict1.items():
            if len(dict1[key]) == 1:
                cormap.append([dict1[key][0],key])
                #[binedge,IRedge]
                continue

            flag1 = 0
            flag2 = 0
            flag3 = 0
            flag4 = 0

            for edge in value:
                IRnodefea0 = testmap.IR_graphwithfea.nodes[edge[0]]['fea']
                IRnodefea1 = testmap.IR_graphwithfea.nodes[edge[1]]['fea']
                binnodefea0 = testmap.bin_graphwithfea.nodes[key[0]]['fea']
                binnodefea1 = testmap.bin_graphwithfea.nodes[key[1]]['fea']

                if len(map_two_BB(binnodefea0,IRnodefea0)) == len(IRnodefea0) == len(binnodefea0) and\
                len(map_two_BB(binnodefea1,IRnodefea1)) == len(IRnodefea1) == len(binnodefea1):
                    if not [edge,key] in cormap:
                        cormap.append([edge,key])
                        flag1 = 1
                    continue

                if map_with_dbgif(filename , funcname , edge[0] , int(key[0],16), db_config) and map_with_dbgif(filename , funcname , edge[1] , int(key[1],16), db_config):
                    if [edge,key] in cormap:
                        continue
                    if flag1 == 0:
                        cormap.append([edge,key])
                        flag2 = 1
                        continue

                if fea_in_list('call',map_two_BB(binnodefea0,IRnodefea0)) and fea_in_list('call',map_two_BB(binnodefea1,IRnodefea1)):
                    if [edge,key] in cormap:
                        continue
                    if not flag1 == flag2 ==0:
                        continue
                    cormap.append([edge,key])
                    flag3 = 1
                    continue

                if fea_in_list('call',map_two_BB(binnodefea0,IRnodefea0)) or fea_in_list('call',map_two_BB(binnodefea1,IRnodefea1)):
                    if [edge,key] in cormap:
                        continue
                    if not flag1 == flag2 == flag3 == 0:
                        continue
                    cormap.append([edge,key])
                    flag4 = 1
                    continue

                # if fea_in_list('call',map_two_BB(binnodefea0,IRnodefea0)):
                #     if [edge,key] in cormap:
                #         continue
                #     else:
                #         if not flag1 == flag2 == flag3 == 0:
                #             continue
                #         if len(map_two_BB(binnodefea1,IRnodefea1)) == len(IRnodefea1):
                #             cormap.append([edge,key])
                #             flag4 = 1
                #             continue

                # if fea_in_list('call',map_two_BB(binnodefea1,IRnodefea1)):
                #     if [edge,key] in cormap:
                #         continue
                #     else:
                #         if not flag1 == flag2 == flag3 == flag4 == 0:
                #             continue
                #         if len(map_two_BB(binnodefea0,IRnodefea0)) == len(IRnodefea0):
                #             cormap.append([edge,key])
                #             continue

                if fea_in_list('cmov',map_two_BB(binnodefea0,IRnodefea0)) or fea_in_list('cmov',map_two_BB(binnodefea1,IRnodefea1)):
                    if [edge,key] in cormap:
                        continue
                    if not flag1 == flag2 == flag3 == flag4 == 0:
                        continue
                    cormap.append([edge,key])

        dict11 = {} 
        corrmap = []
        for node in cormap:
            dict11.setdefault(node[1],[]).append(node[0])
        for key,value in dict11.items():
            if len(dict11[key]) == 1:
                corrmap.append([dict11[key][0],key])
        # print (corrmap)
        
                
        #check if binedge map multiple IRedges in cormap
        dict2 = {}
        corremap = []
        for node in corrmap:
            dict2.setdefault(node[0],[]).append(node[1])
        for  key,value in dict2.items():
            if len(dict2[key]) == 1:
                corremap.append([key,dict2[key][0]])
                continue

            flag1 = 0
            flag2 = 0
            flag3 = 0
            flag4 = 0

            for edge in value:
                IRnodefea0 = testmap.IR_graphwithfea.nodes[key[0]]['fea']
                IRnodefea1 = testmap.IR_graphwithfea.nodes[key[1]]['fea']
                binnodefea0 = testmap.bin_graphwithfea.nodes[edge[0]]['fea']
                binnodefea1 = testmap.bin_graphwithfea.nodes[edge[1]]['fea']

                if len(map_two_BB(binnodefea0,IRnodefea0)) == len(IRnodefea0) == len(binnodefea0) and\
                len(map_two_BB(binnodefea1,IRnodefea1)) == len(IRnodefea1) == len(binnodefea1):
                    if not [key,edge] in corremap:
                        corremap.append([key,edge])
                        flag1 = 1
                    continue

                if map_with_dbgif(filename , funcname , key[0] , int(edge[0],16), db_config) and map_with_dbgif(filename , funcname , key[1] , int(edge[1],16), db_config):
                    if [key,edge] in corremap:
                        continue
                    if flag1 == 0:
                        corremap.append([key,edge])
                        continue
                
                if fea_in_list('call',map_two_BB(binnodefea0,IRnodefea0)) and fea_in_list('call',map_two_BB(binnodefea1,IRnodefea1)):
                    if [key,edge] in corremap:
                        continue
                    if not flag1 == flag2 == 0: 
                        continue
                    corremap.append([key,edge])
                    flag3 = 1
                    continue

                if fea_in_list('call',map_two_BB(binnodefea0,IRnodefea0)) or fea_in_list('call',map_two_BB(binnodefea1,IRnodefea1)):
                    if [key,edge] in corremap:
                        continue
                    if not flag1 == flag2 == flag3 == 0: 
                        continue
                    corremap.append([key,edge])
                    flag4 = 1
                    continue

                # if fea_in_list('call',map_two_BB(binnodefea0,IRnodefea0)):
                #     if [key,edge] in corremap:
                #         continue
                #     else:
                #         if len(map_two_BB(binnodefea1,IRnodefea1)) == len(IRnodefea1):
                #             corremap.append([key,edge])
                #             continue

                # if fea_in_list('call',map_two_BB(binnodefea1,IRnodefea1)):
                #     if [key,edge] in corremap:
                #         continue
                #     else:
                #         if len(map_two_BB(binnodefea0,IRnodefea0)) == len(IRnodefea0):
                #             corremap.append([key,edge])
                #             continue

                if fea_in_list('cmov',map_two_BB(binnodefea0,IRnodefea0)) or fea_in_list('cmov',map_two_BB(binnodefea1,IRnodefea1)):
                    if [key,edge] in corremap:
                        continue
                    if not flag1 == flag2 == flag3 == flag4 == 0: 
                        continue
                    corremap.append([key,edge]) 
                    continue

        dict22 = {}
        for node in corremap:
            dict22.setdefault(node[0],[]).append(node[1])
        for  key,value in dict22.items():
            if len(dict22[key]) == 1:
                correctmap.append([key,dict22[key][0]])
        # print(corremap)
        # print(correctmap)



        for node in correctmap:
            if not node[1][0] in mapped_IRnode.setdefault(node[0][0],[]):
                mapped_IRnode.setdefault(node[0][0],[]).append(node[1][0])
            if not node[1][1] in mapped_IRnode.setdefault(node[0][1],[]):
                mapped_IRnode.setdefault(node[0][1],[]).append(node[1][1])

            if not node[0][0] in mapped_binnode.setdefault(node[1][0],[]):
                mapped_binnode.setdefault(node[1][0],[]).append(node[0][0])
            if not node[0][1] in mapped_binnode.setdefault(node[1][1],[]):
                mapped_binnode.setdefault(node[1][1],[]).append(node[0][1])
  
        #the first bb and the ret bb is mapped
        intlabel = []
        intaddr = []
        binret = 0
        for node in testmap.IR_graphwithfea.nodes.keys():
            intlabel.append(int(node))
        for node in testmap.bin_graphwithfea.nodes.keys():
            intaddr.append(int(node,16))
            if 'retn' in testmap.bin_graphwithfea.nodes[node]['fea']:
                binret = node
        IRret = str(max(intlabel))
        IRstart = str(min(intlabel))
        binstart = str(hex(min(intaddr)))
        if binret != 0:
            mapped_IRnode.setdefault(IRret,[]).append(binret)
        if not binstart in mapped_IRnode.setdefault(IRstart,[]):
            mapped_IRnode.setdefault(IRstart,[]).append(binstart)

        mapped_binnode.setdefault(binstart,[]).append(IRstart)
        mapped_binnode.setdefault(binret,[]).append(IRret)


        # print(max(intlabel),min(intlabel))
        # print(max(intaddr),min(intaddr))

            # if not testmap.IR_graphwithfea.succ[node]:
            #     IRret.append(node)
            #     binret = []
            #     for node1 in testmap.bin_graphwithfea.nodes.keys():
            #         if not testmap.bin_graphwithfea.succ[node1]:
            #             binret.append(node1)
            #     #in case tailcall BB is mixed
            #     if len(binret) == 1:
            #         mapped_IRnode.setdefault(node,[]).append(binret[0])
            #         mapped_binnode.setdefault(node1,[]).append(binret[0])
            # if not testmap.IR_graphwithfea.pred[node]:
            #     binstart = []
            #     for node2 in testmap.bin_graphwithfea.nodes.keys():
            #         if not testmap.bin_graphwithfea.pred[node2]:
            #             binstart.append(node2)
            #     if len(binstart) == 1:
            #         mapped_IRnode.setdefault(node,[]).append(binstart[0])
            #         mapped_binnode.setdefault(binstart[0],[]).append(node) 
            # print (node[0][0])
            # print ('\n')
        # for node in testmap.IR_graphwithfea.nodes:
        #     print(node,testmap.IR_graphwithfea.nodes[node]['fea'])
        # for node in mapped_IRnode.items():
        #     print (node)
        #     print ('\n')
        # len1 = 30 - len(testmap.func_name)
        # noom = ' '
        # for i in range(0,len1):
        #     noom = noom + ' '
        # print (testmap.func_name,end = noom)
        # print (len(mapped_IRnode.keys()),len(testmap.IR_graphwithfea.nodes),len(mapped_IRnode.keys())/len(testmap.IR_graphwithfea.nodes))
        # print(noom,len(mapped_binnode.keys()),len(testmap.bin_graphwithfea.nodes),len(mapped_binnode.keys())/len(testmap.bin_graphwithfea.nodes))
        # for node in correctmap:
        #     print (node)
        #     print (IR_edgewith_fea[node[0]])
        #     print (bin_edgewith_fea[node[1]])
        #     print('\n')
        
        # print ('uncertainmap')
        
        # edgedict = {}
        # for node in mapped_edge:
        #     edgedict.setdefault(node[0],[]).append(1)
        #     if not node in correctmap:
        #         print (node)
        #         print (IR_edgewith_fea[node[0]])
        #         print (bin_edgewith_fea[node[1]])
        #         print('\n')
        
        # print(len(edgedict.keys()))


        # for node in mapped_edge:
        #     print (node)
        #     print (IR_edgewith_fea[node[0]])
        #     print (bin_edgewith_fea[node[1]])
        #     print ('\n')
        # print (len(mapped_edge))
    cmp_edgewithfea()
   
    #take debug_info into account

    # def map_with_debuginfo():
    #     mapped_IR_bin_BB = dbgif.cmp_distinct_bbs_in_f(testmap.file_name, testmap.func_name, testmap.bin_cfg.graph.nodes, db_config)
    #     for item in mapped_IR_bin_BB.items():
    #         print (item)
    #     print(mapped_IR_bin_BB)
    # map_with_debuginfo()


    # real_f_path = os.path.realpath(__file__)
    # this_path = real_f_path[:real_f_path.rfind('/')]
    IRmaplist = []
    binmaplist = []
    for node in testmap.IR_graphwithfea.nodes.keys():
        testmap.IR_graphwithfea.nodes[node]['mapped'] = 0
        #if used == 1,the pred and succ of the node are all mapped
        testmap.IR_graphwithfea.nodes[node]['used'] = 0

    for key,value in mapped_IRnode.items():
        testmap.IR_graphwithfea.nodes[key]['mapped'] = 1

        testmap.IR_graphwithfea.nodes[key]['color'] = 'green'
       
        for addr in value:
            testmap.bin_graphwithfea.nodes[addr]['mapped'] = 1
            testmap.bin_graphwithfea.nodes[addr]['color'] = 'green'

    def map_after_edge():
        list1 = list(mapped_IRnode.keys())
        count1 = 0
        count2 = 0
        count3 = 0
        for node in list1:
            dict = {}
            dict1 = {}
            dict2 = {}
            flag1 = 0
            flag2 = 0
            
            for node1 in testmap.IR_graphwithfea.successors(node):       
                
                # if testmap.IR_graphwithfea.nodes[node]['used'] == 1:
                #     break
                # if not node1 in mapped_IRnode.keys():
                
                # if node == '198':
                #     print(node1)
                #     count3 = count3 + 1
                for binmapped in mapped_IRnode[node]:
                    # if node == '198':
                    #     count1 = count1 + 1
                    #     print('111111')
                    #     print(mapped_IRnode[node])
                    #     print(binmapped,testmap.bin_graphwithfea.nodes[binmapped]['fea'])
                    #     print('\n')
                    if map_two_BB(testmap.IR_graphwithfea.nodes[node1]['fea'],testmap.bin_graphwithfea.nodes[binmapped]['fea'])\
                                and len(map_two_BB(testmap.IR_graphwithfea.nodes[node1]['fea'],testmap.bin_graphwithfea.nodes[binmapped]['fea'])) ==\
                                    len(testmap.IR_graphwithfea.nodes[node1]['fea']):
                        if not node1 in mapped_IRnode.keys():
                            dict.setdefault(node1,[]).append(binmapped)

                    for node2 in testmap.bin_graphwithfea.successors(binmapped):
                
                        if not node2 in mapped_binnode.keys():
                            # print('succs',node,node1,node2)
                            # if node == '198':
                            #     count2 = count2 + 1
                            #     print(node2,testmap.bin_graphwithfea.nodes[node2]['fea'])
                            #     print('\\')
                            if map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node2]['fea'])\
                                and len(map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node2]['fea'])) ==\
                                    len(testmap.bin_graphwithfea.nodes[node2]['fea']):
                                if not node2 in dict.setdefault(node,[]):
                                    dict.setdefault(node,[]).append(node2)
                             
                                
                            if map_two_BB(testmap.IR_graphwithfea.nodes[node1]['fea'],testmap.bin_graphwithfea.nodes[node2]['fea']):
                                if not node1 in mapped_IRnode.keys():
                                    dict.setdefault(node1,[]).append(node2)
                                    flag1 = 1 
                            
                            if len(testmap.IR_graphwithfea.nodes[node1]['fea']) == len(testmap.bin_graphwithfea.nodes[node2]['fea']) == 0:
                                if not node1 in mapped_IRnode.keys():
                                    dict1.setdefault(node1,[]).append(node2)

                
                if len(dict.setdefault(node1,[])) + len(dict.setdefault(node,[])) > 0:
                    if len(dict.setdefault(node1,[])) == 1:
                        mapped_IRnode.setdefault(node1,[]).append(dict[node1][0])
                        list1.append(node1)
                        mapped_binnode.setdefault(dict[node1][0],[]).append(node1)
                        # print(node,'successors')
                        # print(map_two_BB(testmap.IR_graphwithfea.nodes[node1]['fea'],testmap.bin_graphwithfea.nodes[dict[node1][0]]['fea']))
                        # print(node1,dict[node1][0])
                    if len(dict.setdefault(node,[])) >= 1:
                        for nodebin in dict.setdefault(node,[]):
                            if not nodebin in mapped_IRnode.setdefault(node,[]):
                                mapped_IRnode.setdefault(node,[]).append(nodebin)
                                mapped_binnode.setdefault(nodebin,[]).append(node)
                        # print(node,'successors')
                        # print(map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[dict[node][len(dict[node])-1]]['fea']))
                        # print(node,dict[node])
                
                if len(dict1.setdefault(node1,[])) == 1:
                    mapped_IRnode.setdefault(node1,[]).append(dict1[node1][0])
                    list1.append(node1)
                    mapped_binnode.setdefault(dict1[node1][0],[]).append(node1)


            for node3 in testmap.IR_graphwithfea.predecessors(node):
                flag = 0
                # if testmap.IR_graphwithfea.nodes[node]['used'] == 1:
                #     break
                # if not node3 in mapped_IRnode.keys():
                    
                for binmapped in mapped_IRnode[node]:
                    if map_two_BB(testmap.IR_graphwithfea.nodes[node3]['fea'],testmap.bin_graphwithfea.nodes[binmapped]['fea'])\
                                and len(map_two_BB(testmap.IR_graphwithfea.nodes[node3]['fea'],testmap.bin_graphwithfea.nodes[binmapped]['fea'])) ==\
                                    len(testmap.IR_graphwithfea.nodes[node3]['fea']):
                        if not node3 in mapped_IRnode.keys():
                            dict.setdefault(node3,[]).append(binmapped)
                    for node4 in testmap.bin_graphwithfea.predecessors(binmapped):
                        if not node4 in mapped_binnode.keys():
                            # print('pred',node,node4)
                            
                            if map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node4]['fea'])\
                                and len(map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node4]['fea'])) ==\
                                    len(testmap.bin_graphwithfea.nodes[node4]['fea']):
                                if  not node4 in dict.setdefault(node,[]):
                                    dict.setdefault(node,[]).append(node4)
                                
                                
                            if map_two_BB(testmap.IR_graphwithfea.nodes[node3]['fea'],testmap.bin_graphwithfea.nodes[node4]['fea']):
                                if not node3 in mapped_IRnode.keys():
                                    if len(testmap.IR_graphwithfea.pred[node]) <= 10 or \
                                        len(map_two_BB(testmap.IR_graphwithfea.nodes[node3]['fea'],testmap.bin_graphwithfea.nodes[node4]['fea']))>=2 \
                                        or [fea for fea in map_two_BB(testmap.IR_graphwithfea.nodes[node3]['fea'],testmap.bin_graphwithfea.nodes[node4]['fea']) \
                                            if '0' in fea ] == []:
                                        dict.setdefault(node3,[]).append(node4)

                            if len(testmap.IR_graphwithfea.nodes[node3]['fea']) == len(testmap.bin_graphwithfea.nodes[node4]['fea']) == 0:
                                if not node3 in mapped_IRnode.keys():
                                    dict2.setdefault(node3,[]).append(node4)
            
                if len(dict.setdefault(node3,[])) + len(dict.setdefault(node,[])) > 0:
                    if len(dict.setdefault(node3,[])) == 1:
                        mapped_IRnode.setdefault(node3,[]).append(dict[node3][0])
                        list1.append(node3)
                        mapped_binnode.setdefault(dict[node3][0],[]).append(node3)
                    if len(dict.setdefault(node,[])) >= 1:
                        for binnode in dict.setdefault(node,[]):
                            if not binnode in mapped_IRnode.setdefault(node,[]):
                                mapped_IRnode.setdefault(node,[]).append(binnode)
                                mapped_binnode.setdefault(binnode,[]).append(node)
                if len(dict2.setdefault(node3,[])) == 1:
                    mapped_IRnode.setdefault(node3,[]).append(dict2[node3][0])
                    list1.append(node3)
                    mapped_binnode.setdefault(dict2[node3][0],[]).append(node3)
            
            # print(node,dict)
        # print(count3,count1,count2)
    map_after_edge()
    
    len1 = 30 - len(testmap.func_name)
    noom = ' '
    for i in range(0,len1):
        noom = noom + ' '
    print (testmap.func_name,end = noom)
    print (len(mapped_IRnode.keys()),len(testmap.IR_graphwithfea.nodes),len(mapped_IRnode.keys())/len(testmap.IR_graphwithfea.nodes))
    print ('                               ',end = '')
    print(len(mapped_binnode.keys()),len(testmap.bin_graphwithfea.nodes),len(mapped_binnode.keys())/len(testmap.bin_graphwithfea.nodes))
    # print(testmap.bin_graphwithfea.nodes)
    # for node in mapped_IRnode.items():
    #         print (node)
    #         print ('\n')
    # for node in mapped_binnode.items():
    #         print (node)
    #         print ('\n')

    # for node in testmap.bin_graphwithfea.nodes.keys():
    # print(testmap.IR_graphwithfea.succ['302'])
    # if not testmap.IR_graphwithfea.succ['302']:
    #     print(1)
    for key,value in mapped_IRnode.items():
        testmap.IR_graphwithfea.nodes[key]['mapped'] = 1

        testmap.IR_graphwithfea.nodes[key]['color'] = 'green'
        for addr in value:
            testmap.bin_graphwithfea.nodes[addr]['mapped'] = 1
            testmap.bin_graphwithfea.nodes[addr]['color'] = 'green'


    def draw_IR_bin():
        A = nx.nx_agraph.to_agraph(testmap.bin_graphwithfea)

        A.layout('dot')
        A.draw( this_path + '/graphs/bin-' + testmap.func_name + '.png')

        B = nx.nx_agraph.to_agraph(testmap.IR_graphwithfea)

        B.layout('dot')

        B.draw( this_path + '/graphs/IR-' + testmap.func_name + '.png')
    # draw_IR_bin()

    return(len(mapped_IRnode.keys())/len(testmap.IR_graphwithfea.nodes),len(mapped_binnode.keys())/len(testmap.bin_graphwithfea.nodes))

# def test_feabbnum(addr):
#     featest = easymap(addr)
#     count = 0
#     proportion = 0
#     for node in featest.bin_graphwithfea.nodes:
#         if featest.bin_graphwithfea.nodes[node]['fea']:
#             count = count + 1
#             # print(featest.bin_graphwithfea.nodes[node]['fea'])
#     if len(featest.bin_graphwithfea.nodes) == 0:
#         proportion = 'nope'
#     else:
#         proportion = count/len(featest.bin_graphwithfea.nodes)
#     print(featest.func_name,count,len(featest.bin_graphwithfea.nodes),proportion)
# count = 1
# addrs = []
def test_new_addr():

    with open('/home/seclab/dingzhu/gitpro/git2/new_addr.txt','r') as f:
        addrs = f.readlines()
    ave1 = 0
    ave2 = 0
    count = 0
    for addr in addrs:
        # print (count)
        irpro,binpro = test(int(addr,16))
        ave1 = ave1 + irpro
        ave2 = ave2 + binpro
        count = count + 1
    print(ave1/count,ave2/count)

# test_new_addr()
    # count = count + 1
# test_feabbnum(0xffffffff811cc210)
# test_feabbnum(0xffffffff811cc210)
# putname
# test(0xffffffff81219140)
# test(0xffffffff811cb3dd)
# test(0xffffffff811cc210)
# test(0xffffffff811cca70)
# test(0xffffffff811cf5cc)
# patn_openat
# test(0xffffffff8121b4bb)
# unwind_next_frame
# test(0xffffffff8105cc6d)
# get_unmapped_area
# test(0xffffffff811cc89c)
# getname_flags
# test(0xffffffff81218f84)
# test(0xffffffff811cb425)
# may_open
# test(0xffffffff812205b0)
# free_debug_processing
# test(0xffffffff811ff60e)
# def map_graph(IR_graph,bin_graph):
#     #map start from the first block
#     mapwithfea = easymap(addr)
#     def map_graph_from_node(irnode,binnode):
        

