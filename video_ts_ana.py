# -*- coding: utf-8 -*-
# @Time    : 2019-10-14 9:36
# @Author  : RichardoMu
# @File    : video_ts_ana.py
# @Software: PyCharm

import os
from data_struct import *
flag_list = [0,0,0]
# PAT是否解析了
PAT_analysis_flag = 0
# PAT节目数组
TS_program = []
# 没有重复
TS_program_with = []
# PMT element thing
TS_Stream_type = []
# 无重复
TS_Stream_type_with = {}
# TS_Stream_type_struct = []
# 找0x47 发现包全是204一组的，即都加上了crc
# 第二个为188一组的
def find_len_of_packet(folder,file_list,i):
    start = 0
    len1 = 188
    # len2 = 204
    with open(os.path.join(folder,file_list[i]), 'rb') as f:
        section = f.read(len1)
        while len(section) == len1 :
            # for c in section:
            if section[0] == 0x47:
                print("%03d "%(start))
            # offset = offset+1
            section = f.read(188)
            start += 1
# 找ts流有什么类型的包
"""
[(0, 1988), (16, 200), (17, 200), (18, 2273), (20, 36), (39, 360), (256, 822), 
(273, 31019), (276, 6904), (512, 3288), (528, 1988), (529, 1885674), (532, 12539),
(768, 3288), (784, 1988), (785, 245385), (788, 12595), (8136, 1988), (8176, 822), (8191, 1363987)]
"""
def find_PID(folder,file_list,i):
    total = {}
    k = 188
    with open(os.path.join(folder,file_list[i]), 'rb') as f:
        section = f.read(k)
        while len(section) == k:
            PID = (section[1] & 0x1f) << 8 | section[2]
            if PID in total.keys():
                total[PID] += 1
            else :
                total[PID] = 1
            section = f.read(k)
    # 将字典按照值排序 或者 key排序
    print(sorted(total.items(), key=lambda x: x[0]))
def get_PID(buffer):
    # print( (buffer[1] & 0x1f) << 8 | buffer[2])
    return (buffer[1] & 0x1f) << 8 | buffer[2]
def get_PAT(buffer,i):
    # PAT已经解析，无需解析第二次
    global PAT_analysis_flag
    PAT_analysis_flag =1

    Pat_program = {'program_number':0,'program_map_PID':0}
    PAT_packet = PAT_packet_data()
    pat1 = PAT_packet.make_struct()
    pat1.table_id = buffer[0]
    pat1.section_syntax_indicator = (buffer[1] >> 7)&0x01
    pat1.zero = buffer[1] >> 6 & 0x01
    pat1.reserved1 = buffer[1] >> 4 & 0x03
    pat1.section_length = (buffer[1]&0x0f)<<8 | buffer[2]
    pat1.transport_stream_id = buffer[3]<<8 | buffer[4]
    pat1.reserved2 = buffer[5]>>6
    pat1.version_number = (buffer[5]>>1)&0x1f
    # print(buffer[5])
    pat1.current_next_indicator = buffer[5]&0x01
    pat1.section_number = buffer[6]
    pat1.last_section_number = buffer[7]
    length = 3 + pat1.section_length
    if i ==0:
        pat1.CRC_32 = (buffer[length-4] & 0x000000ff) <<24 \
                      | (buffer[length-3]&0x000000ff)<<16 \
                      | (buffer[length-2]&0x000000ff)<<8 \
                      | (buffer[length-1]&0x000000ff)
    for n in range(0,pat1.section_length-12,4):
        program_num = buffer[8+n]<<8 | buffer[9+n]
        pat1.reserved3 = buffer[10+n]>>5
        if (program_num==0x00):
            pat1.network_id_or_program_map_PID = (buffer[10+n]&0x1f)<<8 | buffer[11+n]
            # Ts_network_Pid =
            Ts_network_Pid_dict = {'program_number':0x0,'NIT_PID':pat1.network_id_or_program_map_PID}# 记录该TS流的网络PID and save
            pat1.program.append(Ts_network_Pid_dict)
            print("pat1.network_PID:0x%x\n"%(pat1.network_id_or_program_map_PID))
        else:
            Pat_program['program_map_PID'] = (buffer[10+n]&0x1f)<<8 | buffer[11+n]
            Pat_program['program_number'] = program_num
            pat1.program.append(Pat_program)
            TS_program.append(Pat_program)

        for pat in TS_program:
            a = (pat['program_map_PID'],pat['program_number'])
            if a not in TS_program_with:
                TS_program_with.append(a)


    print(TS_program_with)
    print("*"*80)
    print("PAT")
    pat1.list_all_member()
    print("\n")
    print("*"*80)

    list_ = []
    for k in TS_program_with:
        list_.append(k[0])
    global TS_Stream_type_with
    TS_Stream_type_with = dict.fromkeys(list_)
    for i in range(len(TS_Stream_type_with)):
        TS_Stream_type_with[i] = []
def get_PMT(buffer,flag,name):
    Ts_PMT_Stream = {"stream_type":0,"elementarv_PID":0,"ES_info_lenth":0,
                     # "descriptor":0
                     }
    PMT_packet = PMT_packet_data()
    pam1 = PMT_packet.make_struct()
    pam1.table_id = buffer[0]
    pam1.section_syntax_indicator = buffer[1]>>7
    pam1.zero = buffer[1]>>6 & 0x01
    pam1.reserved1 = buffer[1]>>4 &0x03
    pam1.section_length = (buffer[1]& 0x0f)<<8 | buffer[2]
    pam1.program_number = buffer[3]<<8 | buffer[4]
    pam1.reserved2 = buffer[5]>>6
    pam1.version_number = buffer[5]>>1&0x1f
    pam1.current_next_indicator = buffer[5]&0x01
    pam1.section_number = buffer[6]
    pam1.last_section_number = buffer[7]
    pam1.PCR_PID = (buffer[8]<<8| buffer[9])&0x1fff
    # PCRID = pam1.PCR_PID
    pam1.reserved4 = buffer[10]>>4
    pam1.program_info_length = (buffer[10]&0x0f)<<8 | buffer[11]
    len = pam1.section_length+3
    if flag == 0:
        pam1.CRC_32 = (buffer[len-4]&0x000000ff)<<24 \
                      | (buffer[len-3]&0x000000ff)<<16 \
                      | (buffer[len-2]&0x000000ff)<<8 \
                      | (buffer[len-1]& 0x000000ff)
    pos = 12
    if (pam1.program_info_length!=0):
        pos += pam1.program_info_length
    while(pos<= (pam1.section_length+2)-4):
        Ts_PMT_Stream["stream_type"] = buffer[pos]
        pam1.reserved5 = buffer[pos+1] >>5
        Ts_PMT_Stream["elementarv_PID"] = (((buffer[pos+1]&0x03) << 8)|buffer[pos+2])&0x1fff
        pam1.reserved6 = buffer[pos+3]>>4
        Ts_PMT_Stream["ES_info_lenth"] = (buffer[pos+3] & 0x0f) << 8 | buffer[pos+4]
        pos += 5
        if Ts_PMT_Stream not in pam1.PMT_Stream:
            pam1.PMT_Stream.append(Ts_PMT_Stream)
        TS_Stream_type.append(Ts_PMT_Stream)
        # print(TS_Stream_type_with)
        if Ts_PMT_Stream not in TS_Stream_type_with[name]:
            TS_Stream_type_with[name].append(Ts_PMT_Stream)
    if flag_list[name]==0:
        print("*" * 80)
        print("PMT")
        pam1.list_all_member()
        print('\n')
        print("*" * 80)
        flag_list[name] = 1


def Process_Packet(buffer,i):
    # buffer is
    # 如果PID为0x0000，则packet data为PAT信息，去除包头四个字节
    PID = get_PID(buffer)
    if PID==0X0000 and (PAT_analysis_flag == 0):
        get_PAT(buffer[5:],i) # 4个字节是头文件 32位 PAT去掉两个字节的无用信息 16位  则从第49位开始传输
        return 0
    return 1
def analysis_PMT(folder,file_list,flag):
    read_length = 188 if flag==1 else 204
    with open(os.path.join(folder,file_list[flag]),'rb') as f:
            buffer = f.read(read_length)
            while len(buffer) == read_length:
                PID = get_PID(buffer)
                for i in range(len(TS_program_with)):
                    if PID == TS_program_with[i][0]:
                        get_PMT(buffer=buffer[5:],flag=flag,name=i)
                buffer = f.read(read_length)
def main():
    # 当期目录
    cwd = os.getcwd()
    # 找到视频所在地址
    folder = os.path.join(cwd,'ts')
    file_list = []
    for name in os.listdir(folder):
        file_list.append(name)
    # find_PID(folder,file_list,1)
    # 0  -> Contents1 HD&SD&1SEG.ts 1 -> 包含错误包码流没有输出.ts
    flag = 1
    with open(os.path.join(folder,file_list[flag]),'rb') as f:
        read_length = 188 if flag == 1 else 204
        buffer = f.read(read_length)
        while len(buffer)==read_length:
        # 解析一次PAT就可以了
            if not Process_Packet(buffer,flag):
                break
            buffer = f.read(read_length)
    analysis_PMT(folder,file_list,flag)
    print(TS_Stream_type_with)
if __name__ == '__main__':
    main()

