import os
import pathlib
import subprocess
import json

real_f_path = os.path.realpath(__file__)
this_path = real_f_path[:real_f_path.rfind('/')]

"""
generate IR_feartures_info by ./IR_info/IRBBpe;
store it as json file in ./IR_info
"""

def gen_bc_file(bc_file):
    cmd = 'sh %s/IR_info/extract_bc.sh ' % (this_path) + bc_file
    status = subprocess.getstatus(cmd)
    if status != 0:
        print(bc_file, ' can not be extracted')
        return False
    return True 

def get_IR_info(cfilename):
    if cfilename[-2:] != '.c':
        print(cfilename, ' is not a name of c file')
        return

    # search result_file in  '$this/IR_info' 
    info_f = this_path + '/IR_info/' + cfilename[cfilename.find('linux/'):].replace('/','+').replace('.c','.json')
    # if there is such json_file, get it and exit 
    if pathlib.Path(info_f).is_file():
        with open(info_f,'rb') as IR_features_f:
            IR_features = json.load(IR_features_f)
            # print('Got it from file.')
        return IR_features
    
    # if there is no, go to generate it 
    # - first checkout the bc_file
    bc_fn = cfilename[:-2] + '.o.bc'
    if not pathlib.Path(bc_fn).is_file():
        print(bc_fn,' not exists')
        # - generate the bc file by extract_bc.sh
        if not gen_bc_file(bc_fn):
            return
    
    # - generate IR_feartures_info by ./IR_info/IRBBpe
    cmd = this_path + '/IR_info/'+ 'IRBBpe8.11 -t ' + bc_fn
    status, output = subprocess.getstatusoutput(cmd)
    if status != 0:
        print('ERR: ',cmd)
        return
    IR_features = json.loads(output)
    # print('fea:',IR_features)
    with open(info_f,'w') as f:
        json.dump(IR_features, f, indent=0)

    return IR_features

if __name__ == "__main__":           
    get_IR_info('/home/seclab/xujianhao/linux/mm/mmap.c')
    # get_IR_info('~/xujianhao/linux/mm/slubsss.c')
