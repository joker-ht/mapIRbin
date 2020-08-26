import networkx as nx
import xmlrpc.client
# xmlrpclib.Marshaller.dispatch[type(0L)] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)

host = "http://114.212.85.187:12345"

def get_CFG_edges(inst_addr, bin_ida_server=None):
    if bin_ida_server is None:
        bin_ida_server = host
    server = xmlrpc.client.ServerProxy(bin_ida_server)
    edges0 = server.get_CFG_edges(hex(inst_addr))
    return edges0

def get_CFG(inst_addr, bin_ida_server=None):
    """
    get the CFG of the given addr's function
    """
    if bin_ida_server is None:
        bin_ida_server = host
    server = xmlrpc.client.ServerProxy(bin_ida_server)
    edges = get_CFG_edges(inst_addr)
    CFG = nx.DiGraph()
    CFG.add_edges_from(edges)
    # print (CFG.nodes)
    return CFG


def get_func_name(inst_addr, bin_ida_server=None):
    if bin_ida_server is None:
        bin_ida_server = host
    server = xmlrpc.client.ServerProxy(bin_ida_server)
    func_name = server.get_func_name(hex(inst_addr))
    return func_name

def get_func_features(inst_addr, bin_ida_server=None):
    if bin_ida_server is None:
        bin_ida_server = host
    server = xmlrpc.client.ServerProxy(bin_ida_server)
    func_feas = server.get_func_features(hex(inst_addr))
    return func_feas

def get_bb_insts(inst_addr, bin_ida_server=None):
    if bin_ida_server is None:
        bin_ida_server = host
    server = xmlrpc.client.ServerProxy(bin_ida_server)
    bb_insts = server.get_bb_insts(hex(inst_addr))
    return bb_insts

def get_func_insts(inst_addr, bin_ida_server=None):
    if bin_ida_server is None:
        bin_ida_server = host
    server = xmlrpc.client.ServerProxy(bin_ida_server)
    func_insts = server.get_func_insts(hex(inst_addr))
    return func_insts
    
def killRPC(bin_ida_server=None):
    if bin_ida_server is None:
        bin_ida_server = host
    server = xmlrpc.client.ServerProxy(bin_ida_server)
    server.kill()

if __name__ == "__main__":
    # print('start')
    # addr = 0xffffffff8121914b
    # print(get_func_name(addr))
    # print(get_bb_insts(addr)) 
    print(get_CFG_edges(0xffffffff81219140))
    # print(get_CFG(0xffffffff81219140))

    # killRPC()
