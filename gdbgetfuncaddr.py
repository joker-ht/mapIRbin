import gdb
sechkbcfile = '/home/seclab/dingzhu/sechk-indirect.txt'
out = '/home/seclab/dingzhu/sechk-indirect-addr.txt'
def get_addr_from_funcname(filename,output):

    with open(filename,'r') as f:
        lines = f.readlines()
    funcname = []
    for line in lines:
        funcname.append(line.split('%')[0])
    funcname = list(set(funcname))
    # print(funcname)
    # print(funcname)
    addrlist = []
    for node in funcname:
        cmd = 'print ' + node
        gdbstr = gdb.execute(cmd,to_string = True)
        addr0 = gdbstr.split('0x')[1]
        addr1 = addr0.split(' ')[0]
        addr2 = '0x' + addr1
        addrlist.append(addr2)
        # print (addr2)
        # print(cmd)
    with open(output,'wb') as f:
        for node in addrlist:
            f.write(node + '\n')

get_addr_from_funcname(sechkbcfile,out)