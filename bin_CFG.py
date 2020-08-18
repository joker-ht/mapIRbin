import os
import networkx as nx
import IDA_RPC_client as ida

real_f_path = os.path.realpath(__file__)
this_path = real_f_path[:real_f_path.rfind('/')]

def get_bin_CFG(inst_addr, bin_ida_server):
    return ida.get_CFG(inst_addr, bin_ida_server)


def get_func_name(inst_addr, bin_ida_server):  
    return ida.get_func_name(inst_addr, bin_ida_server)

def get_func_features(inst_addr, bin_ida_server):
    return ida.get_func_features(inst_addr, bin_ida_server)

def get_bb_insts(inst_addr, bin_ida_server):
    return ida.get_bb_insts(inst_addr, bin_ida_server)

# def killRPC():
#     server = xmlrpc.client.ServerProxy("http://114.212.81.134:12345")
#     server.kill()

def draw_graph(graph, func_name):
    # plt.title(func_name)
    A = nx.nx_agraph.to_agraph(graph)
    # A.layout('dot', args='-Nfontsize=10 -Nwidth=".2" -Nheight=".2" -Nmargin=0 -Gfontsize=8')
    A.layout('dot')
    # print ('print graph start')
    # print (A)
    # print(A.edges)
    # print ('print graph end')
    A.draw( this_path + '/graphs/bin-' + func_name + '.png')


class bin_CFG(object):
    """ build CFG of a given function """
    def __init__(self, file_name, func_name, inst_addr, bin_ida_server):
    # inst_addr can be any inst in the func
    # bin_ida_server : for example "http://114.212.81.134:12345" 
        self.file_name = file_name
        self.func_name = func_name
        self.graph = get_bin_CFG(inst_addr, bin_ida_server)
        self.node_features_map = get_func_features(inst_addr, bin_ida_server)


if __name__ == "__main__":
    addr = 0xffffffff811ff3f7
    addr = 0xffffffff811c25e9
    addr = 0xffffffff811cc210
    file_name = 'unknown'
    bin_ida_server = "http://114.212.81.134:12345"
    funcname = get_func_name(addr, bin_ida_server)
    print(funcname)
    
    cfg_obj = bin_CFG(file_name, funcname, addr, bin_ida_server)
    print(cfg_obj.node_features_map)
    # draw_graph(cfg_obj.graph, funcname)
    for node in cfg_obj.graph.nodes:
        print (node)
