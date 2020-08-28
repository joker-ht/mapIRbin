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

#if BB1 and BB2 have intersection  
def map_two_BB(IR_BB_Fea,bin_BB_Fea):
    map_fea = []
    if IR_BB_Fea and bin_BB_Fea:
        map_fea = list(set(IR_BB_Fea)&set(bin_BB_Fea))

    if map_fea:
        return map_fea
    else:
        return False


class easymap(mapbb.mapping):
    def __init__(self, inst_addr, db_config = None, bin_ida_server = None, bin_name = None):
        super().__init__(inst_addr, db_config, bin_ida_server, bin_name)
        self.IR_graphwithfea = add_fea_to_graph(self.IR_cfg.graph,self.IR_cfg.node_features_map)
        self.bin_graphwithfea = add_fea_to_graph(self.bin_cfg.graph,self.bin_cfg.node_features_map)
    def nor_bin(self):
        change_hex_to_dec(self)

def add_fea_to_graph(G,feadic):
    for node in G.nodes:
        # print(node)
        G.nodes[node]['fea'] = feadic.setdefault(node,[])
        G.nodes[node]['label'] = node + '\n' + str(G.nodes[node]['fea'])
    return G

#imm fea in bin is hex,change it to dec 
def change_hex_to_dec(mapobj):
    for node in mapobj.bin_graphwithfea.nodes:
        if mapobj.bin_graphwithfea.nodes[node]['fea']:
            for feat in mapobj.bin_graphwithfea.nodes[node]['fea']:
                if '0x' in feat or '2900' in feat:
                    immfea = feat.split('L')[0]
                    memu = feat.split(' ')[0]
                    value = int(immfea.split(' ')[1],16)
                    if 'ffffffff' in feat:
                        value = int(immfea.split(' ')[1],16) - int('0xffffffffffffffff',16) - 1
                    
                    newfea = memu + ' ' + str(value)
                    # print (newfea)
                    mapobj.bin_graphwithfea.nodes[node]['fea'].remove(feat)
                    mapobj.bin_graphwithfea.nodes[node]['fea'].insert(0,newfea)
                if feat == 'test0':
                    mapobj.bin_graphwithfea.nodes[node]['fea'].remove(feat)
                    mapobj.bin_graphwithfea.nodes[node]['fea'].insert(0,'cmp 0')

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

def draw_IR_bin(mapobj):
        A = nx.nx_agraph.to_agraph(mapobj.bin_graphwithfea)

        A.layout('dot')
        A.draw( this_path + '/graphs/bin-' + mapobj.func_name + '.png')

        B = nx.nx_agraph.to_agraph(mapobj.IR_graphwithfea)

        B.layout('dot')

        B.draw( this_path + '/graphs/IR-' + mapobj.func_name + '.png')

def test(addr):
   
    testmap = easymap(addr)
    testmap.nor_bin()
    # for node in testmap.IR_graphwithfea.nodes:
    #     print (node,testmap.IR_graphwithfea.nodes[node]['fea'])
    # print ('\n')
    # for node in testmap.bin_graphwithfea.nodes:
    #     print (node,testmap.bin_graphwithfea.nodes[node]['fea'])
    # print(testmap.IR_cfg.graph.edges)
    _, file_name, _, _ = mapbb.addr2line(addr, db_config, bin_name=None)
    filename = file_name
    funcname = testmap.func_name
        # for node in testmap.IR_graphwithfea.nodes:
        #     print (node,testmap.IR_graphwithfea.nodes[node]['fea'])
    # add_IR_fea()

    #imm fea in bin is hex,let's change it to dec          

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
                mapped_IRnode[node[0][0]].append(node[1][0])
            if not node[1][1] in mapped_IRnode.setdefault(node[0][1],[]):
                mapped_IRnode[node[0][1]].append(node[1][1])

            if not node[0][0] in mapped_binnode.setdefault(node[1][0],[]):
                mapped_binnode[node[1][0]].append(node[0][0])
            if not node[0][1] in mapped_binnode.setdefault(node[1][1],[]):
                mapped_binnode[node[1][1]].append(node[0][1])
  
        #the first bb and the ret bb is mapped
        intlabel = []
        intaddr = []
        binret = 0
        # print(111)
        # print(testmap.IR_graphwithfea.nodes.keys())
     
        for node in testmap.IR_graphwithfea.nodes.keys():
            # print(1)
            # print(node)
            intlabel.append(int(node))
        # print(testmap.bin_graphwithfea.nodes.keys())
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
            mapped_IRnode[IRstart].append(binstart)
        mapped_binnode.setdefault(binstart,[]).append(IRstart)
        mapped_binnode.setdefault(binret,[]).append(IRret)

        # test code
        # for node in mapped_IRnode.items():
        #     print(node)
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
    cmp_edgewithfea()

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
            # print(node)
            dict = {}
            dict1 = {}
            dict2 = {}
            flag1 = 0
            flag2 = 0
            
            # list2 = mapped_IRnode[node]
            # if node == '341':
                # print(1,mapped_IRnode['341'])
            # print(1)
            # print(mapped_IRnode['142'])
            count111 = 0
            for binnode in mapped_IRnode[node]:
                for succsnode in testmap.bin_graphwithfea.successors(binnode):
                    if not succsnode in mapped_binnode.keys():
                        if map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[succsnode]['fea'])\
                            and len(map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[succsnode]['fea'])) ==\
                            len(testmap.bin_graphwithfea.nodes[succsnode]['fea']) \
                            and len([fea for fea in testmap.IR_graphwithfea.nodes[node]['fea'] if fea in  map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[succsnode]['fea'])])\
                            > len([fea for fea in testmap.bin_graphwithfea.nodes[binnode]['fea'] if fea in  map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[succsnode]['fea'])]):
                            if len(testmap.bin_graphwithfea.nodes[succsnode]['fea']) == 1 and map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],\
                                testmap.bin_graphwithfea.nodes[succsnode]['fea']) == ['cmp 2 reg']:
                                count111 += 1
                                # print('count111',node)
                                if count111 < len(testmap.IR_graphwithfea.nodes[node]['fea']):
                                # print(succsnode)
                                    mapped_IRnode[node].append(succsnode)

                                    mapped_binnode.setdefault(succsnode,[]).append(node)
                                else:
                                    break
                            else:
                                mapped_IRnode[node].append(succsnode)
                                mapped_binnode.setdefault(succsnode,[]).append(node)
            # if node == '627':
            #     print ('627',count111,mapped_IRnode[node])
            # if node == '341':
            #     print(2,mapped_IRnode['341'])
            #     print(list2)
            # if node == '639':
            #         print(node,node1,dict.setdefault('647',[]),mapped_IRnode[node])
            unmappednode1 = 0
            totalnode1 = 0
            for node1 in testmap.IR_graphwithfea.successors(node):
                totalnode1 += 1
                if not node1 in mapped_IRnode.keys():
                     unmappednode1 = unmappednode1 + 1
            for node1 in testmap.IR_graphwithfea.successors(node):       
                # if testmap.IR_graphwithfea.nodes[node]['used'] == 1:
                #     break
                # if not node1 in mapped_IRnode.keys():
                
                # if node == '198':
                #     print(node1)
                #     count3 = count3 + 1
                unmappednode2 = 0
                totalnode2 = 0
                for binmapped in mapped_IRnode[node]:
                    totalnode2 += 1
                    for node2 in testmap.bin_graphwithfea.successors(binmapped):
                        if not node2 in mapped_binnode.keys():
                            unmappednode2 = unmappednode2 + 1
                for binmapped in mapped_IRnode[node]:
                    # if node == '341':
                    #     print('111111')
                    #     print(mapped_IRnode[node])
                    #     print(binmapped,testmap.bin_graphwithfea.nodes[binmapped]['fea'])
                    #     print('\n')
                    if totalnode2 == 1:
                        # if node1(succs of irnode) map binnode(binnode which maps irnode)
                        if map_two_BB(testmap.IR_graphwithfea.nodes[node1]['fea'],testmap.bin_graphwithfea.nodes[binmapped]['fea'])\
                            and len(map_two_BB(testmap.IR_graphwithfea.nodes[node1]['fea'],testmap.bin_graphwithfea.nodes[binmapped]['fea'])) ==\
                            len(testmap.IR_graphwithfea.nodes[node1]['fea']) and len(testmap.bin_graphwithfea.nodes[binmapped]['fea']) > \
                            len(testmap.IR_graphwithfea.nodes[node1]['fea']):
                            if not node1 in mapped_IRnode.keys():
                                dict.setdefault(node1,[]).append(binmapped)
                                # if node1 == '647':
                                #     print(binmapped)
                    for node2 in testmap.bin_graphwithfea.successors(binmapped):
                
                        if not node2 in mapped_binnode.keys():
                            # print('succs',node,node1,node2)
                            # if node == '341':
                            #     print(node,node1,binmapped,node2,testmap.bin_graphwithfea.nodes[node2]['fea'])
                            #     print('\\')
                            # if map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node2]['fea'])\
                            #     and len(map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node2]['fea'])) ==\
                            #         len(testmap.bin_graphwithfea.nodes[node2]['fea']):
                            #     if not node2 in dict.setdefault(node,[]):
                            #         dict.setdefault(node,[]).append(node2)
                             
                                
                            if map_two_BB(testmap.IR_graphwithfea.nodes[node1]['fea'],testmap.bin_graphwithfea.nodes[node2]['fea']):
                                if not node1 in mapped_IRnode.keys():
                                    dict.setdefault(node1,[]).append(node2)
                                    flag1 = 1 
                                    continue
                            
                            if len(testmap.IR_graphwithfea.nodes[node1]['fea']) == len(testmap.bin_graphwithfea.nodes[node2]['fea']) == 0:
                                if not node1 in mapped_IRnode.keys():
                                    dict1.setdefault(node1,[]).append(node2)
                                    continue
                            
                            if node1 not in mapped_IRnode.keys() and unmappednode2 == unmappednode1 == 1 and \
                                len(testmap.IR_graphwithfea.nodes[node1]['fea']) <= 2 and len(testmap.bin_graphwithfea.nodes[node2]['fea']) <= 2 and \
                                totalnode1 >= 2 and totalnode2 >=2:
                                print('new rule',node,node1,node2)
                                dict1.setdefault(node1,[]).append(node2)
                            
                
                # if node == '639':
                #     print(node,node1,dict.setdefault(node1,[]),mapped_IRnode[node])
                #     print(dict)
                if len(dict.setdefault(node1,[])) + len(dict.setdefault(node,[])) > 0:
                    if len(dict.setdefault(node1,[])) == 1:
                        mapped_IRnode.setdefault(node1,[]).append(dict[node1][0])
                        list1.append(node1)
                        mapped_binnode.setdefault(dict[node1][0],[]).append(node1)
                        # if node == '341':
                        #     print(node1,dict[node1])
                        # print(node,'successors')
                        # print(map_two_BB(testmap.IR_graphwithfea.nodes[node1]['fea'],testmap.bin_graphwithfea.nodes[dict[node1][0]]['fea']))
                        # print(node1,dict[node1][0])
                    if len(dict.setdefault(node1,[])) > 1:
                        f = 0
                        default = dict.setdefault(node1,[])[0]
                        for n in dict[node1]:
                            if n != default:
                                f = 1
                        if f == 0:
                            mapped_IRnode.setdefault(node1,[]).append(dict[node1][0])
                            list1.append(node1)
                            mapped_binnode.setdefault(dict[node1][0],[]).append(node1)
                    if len(dict.setdefault(node,[])) >= 1:
                        for nodebin in dict.setdefault(node,[]):
                            if not nodebin in mapped_IRnode.setdefault(node,[]):
                                mapped_IRnode.setdefault(node,[]).append(nodebin)
                                mapped_binnode.setdefault(nodebin,[]).append(node)
                                # if node == '341':
                                #     print(node,nodebin)
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
                        unmappednode4 = 0
                        if not node4 in mapped_binnode.keys():
                            # print('pred',node,node4)
                            # 8.24 if fea in binnodepred,in irnode,not in binnode
                            if map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node4]['fea'])\
                                and len([fea for fea in testmap.IR_graphwithfea.nodes[node]['fea'] if fea in map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node4]['fea'])])\
                                > len([fea for fea in testmap.bin_graphwithfea.nodes[node4]['fea'] if fea in map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node4]['fea'])]) \
                                and len(map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node4]['fea'])) ==\
                                len(testmap.bin_graphwithfea.nodes[node4]['fea']):
                                if  not node4 in dict.setdefault(node,[]):
                                    dict.setdefault(node,[]).append(node4)
                                    # print(node,binmapped,node4)
                                    # print(testmap.bin_graphwithfea.nodes[binmapped]['fea'])
                                    # print(map_two_BB(testmap.IR_graphwithfea.nodes[node]['fea'],testmap.bin_graphwithfea.nodes[node4]['fea']))
                                
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
        # test code
        # print('mapafteredge')
        # for node in mapped_IRnode.items():
        #     print(node)
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

    draw_IR_bin(testmap)

    # print(mapped_binnode.keys())
    return(len(mapped_IRnode.keys())/len(testmap.IR_graphwithfea.nodes),len(mapped_binnode.keys())/len(testmap.bin_graphwithfea.nodes),mapped_IRnode,testmap.func_name)
    
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

def test_secheck():

    with open('/home/seclab/dingzhu/sechk-slub-addr.txt','r') as f:
        addrs = f.readlines()
    ave1 = 0
    ave2 = 0
    count = 0
    for addr in addrs:
        # print (count)
        if addr.startswith('0x'):
            irpro,binpro,_,_ = test(int(addr,16))
            ave1 = ave1 + irpro
            ave2 = ave2 + binpro
            count = count + 1
    print(ave1/count,ave2/count)

# test_secheck()

def test_proofsechk():
    with open('/home/seclab/dingzhu/securitychq','r') as f:
        addrs = f.readlines()
    ave1 = 0
    ave2 = 0
    mappedsechck = 0
    count = 0
    label = 0
    for addr in addrs:
        # print (count)
        if addr.startswith('0x'):
            irpro,binpro,mapped_IRnode,func_name = test(int(addr,16))
        else:
            count = count + 1
            funcname = addr.split('%')[0]
            label = addr.split('%')[1]
            label1 = label.strip('\n')
            # print(label,len(label))
            # print(len(label1))
            if funcname == func_name:
                if label1 in mapped_IRnode.keys():
                    # print(label)
                    mappedsechck = mappedsechck + 1
    print(mappedsechck,count,mappedsechck/count)


    # print(ave1/count,ave2/count)

# test_proofsechk()

def test_821(addrfile,sechkfile):
    count = 0
    chkcount = 0
    ave1 = 0
    ave2 = 0
    amount = 0
    with open(addrfile,'r') as f:
        addrs = f.readlines()
    with open(sechkfile,'r') as f:
        funclabel = f.readlines()
    count = len(funclabel)
    funcnames = []
    # for node in funclabel:
    #     funcnames.append(node.split('%')[0])
    for addr in addrs:
        irpro,binpro,mapped_IRnode,func_name = test(int(addr,16))
        ave1 = irpro + ave1
        ave2 = binpro + ave2
        amount = amount + 1
        for node in funclabel:
            funcname = node.split('%')[0]
            label = node.split('%')[1].strip('\n')
            if func_name == funcname:
                if label in mapped_IRnode.keys():
                    chkcount = chkcount + 1
    print(ave1/amount,ave2/amount)
    print('sechk: ',chkcount,count,chkcount/count)

# test_821('/home/seclab/dingzhu/sechk-namei-addr.txt','/home/seclab/dingzhu/sechk-namei.txt')
# test_821('/home/seclab/dingzhu/sechk-inline-addr.txt','/home/seclab/dingzhu/sechk-inode.txt')


def main():
        # count = count + 1
    # test_feabbnum(0xffffffff811cc210)
    # test_feabbnum(0xffffffff811cc210)
    # putname
    # test(0xffffffff81219140)
    # test(0xffffffff811cb3dd)
    test(0xffffffff811cc210)
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
    # unmap_vmas
    # test(0xffffffff811c25d3)
    # error test
    # test(0xffffffff8121f510)
    # test(0xffffffff811fbc80)
    # test(0xffffffff811c2a10)(该函数在bin只有一个BB，导致通过edge构造边时该图为空)
    # test(0xffffffff811c1340)(该函数在bin只有一个BB，导致通过edge构造边时该图为空)
    # test(0xffffffff811c3000)
    # test(0xffffffff812d3d40)(ida解析得到的函数名有问题)
    # test(0xffffffff812d52c0)
    # test(ext4_iomap_end)(IR中只有一个BB，bin也是)
    # def map_graph(IR_graph,bin_graph):
    #     #map start from the first block
    #     mapwithfea = easymap(addr)
    #     def map_graph_from_node(irnode,binnode):
            

    # testmap1 = easymap(0xffffffff812d52c0)
    # print(testmap1.IR_graphwithfea.nodes.keys())
    # print(testmap1.func_name)

if __name__ == "__main__":
    main()