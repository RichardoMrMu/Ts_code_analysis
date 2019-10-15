# -*- coding:utf-8 -*-
# @Time     : 2019-10-14 14:49
# @Author   : Richardo Mu
# @FILE     : data_struct.PY
# @Software : PyCharm

class packet_header(object):
    class Struct(object):
        def __init__(self,sync_byte,
                     transport_error_indicator,
                     payload_unit_start_indicatpr,
                     transport_priority,
                     PID,
                     transport_scrambling_control,
                     adaptation_field_control,
                     continuity_counte
                     ):
            self.sync_byte = sync_byte  # 固定同步字节
            self.transport_error_indicator = transport_error_indicator  # 没有传输错误
            self.payload_unit_start_indicatpr = payload_unit_start_indicatpr  # 在前4个字节后会有一个调整字节。所以实际数据应该为去除
            # 第一个字节后的数据。即上面数据中红色部分不属于有效数据包。
            self.transport_priority = transport_priority  # 传输优先级低
            self.PID = PID  # PID=0x0000说明数据包是PAT表信息
            self.transport_scrambling_control = transport_scrambling_control  # 未加密
            self.adaptation_field_control = adaptation_field_control  # 附加区域控制
            self.continuity_counte = continuity_counte  # 包递增计数器
        def list_all_member(self):
            for i , j in vars(self).items():
                print(i,":  ",j)
    def make_struct(self,sync_byte=0x47,
                     transport_error_indicator=0b0,
                     payload_unit_start_indicatpr=0b0,
                     transport_priority=0b0,
                     PID=0x0000,
                     transport_scrambling_control=0b00,
                     adaptation_field_control=0b01,
                     continuity_counte=0b0000):
        return self.Struct(sync_byte,
                     transport_error_indicator,
                     payload_unit_start_indicatpr,
                     transport_priority,
                     PID,
                     transport_scrambling_control,
                     adaptation_field_control,
                     continuity_counte)
class PAT_packet_data(object):
    class Struct(object):
        def __init__(self,
                   table_id,
                   section_syntax_indicator,
                   zero,
                   reserved1,
                   section_length,
                   transport_stream_id,
                   reserved2,
                   version_number,
                   current_next_indicator,
                   section_number,
                   last_section_number,
                   program_number,
                   reserved3,
                   network_id_or_program_map_PID,
                   CRC_32):
            self.table_id = table_id
            self.section_syntax_indicator = section_syntax_indicator
            self.zero = zero
            self.reserved1 = reserved1
            self.section_length = section_length
            self.transport_stream_id = transport_stream_id
            self.reserved2 = reserved2
            self.version_number= version_number
            self.current_next_indicator = current_next_indicator
            self.section_number = section_number
            self.last_section_number = last_section_number
            # self.program_number = program_number
            self.reserved3 = reserved3
            self.network_id_or_program_map_PID = network_id_or_program_map_PID
            self.CRC_32 = CRC_32
            self.program = []
        def list_all_member(self):
            for i , j in vars(self).items():
                print(i,":  ",j)
    def make_struct(self,table_id=0x00,
                   section_syntax_indicator=0b1,
                   zero=0b0,
                   reserved1=0b11,
                   section_length=0x011,
                   transport_stream_id=0x0001,
                   reserved2=0b11,
                   version_number=0b00000,
                   current_next_indicator=0b1,
                   section_number=0x00,
                   last_section_number=0x00,
                   program_number=0x0000,
                   reserved3=0b111,
                   network_id_or_program_map_PID=0x00,
                   CRC_32=0x0):
        return self.Struct(table_id,
                   section_syntax_indicator,
                   zero,
                   reserved1,
                   section_length,
                   transport_stream_id,
                   reserved2,
                   version_number,
                   current_next_indicator,
                   section_number,
                   last_section_number,
                   program_number,
                   reserved3,
                   network_id_or_program_map_PID,
                   CRC_32)


class PMT_packet_data(object):
    class Struct(object):
        def __init__(self,
                   table_id,
                   section_syntax_indicator,
                   zero,
                   reserved1,
                   section_length,
                   program_number,
                   reserved2,
                   version_number,
                   current_next_indicator,
                   section_number,
                   last_section_number,
                   reserved3,
                   PCR_PID,
                   reserved4,
                   program_info_length,
                   stream_type,
                   reserved5,
                   elementary_PID,
                   reserved6,
                   ES_info_length,
                   CRC_32):
            self.table_id = table_id
            self.section_syntax_indicator = section_syntax_indicator
            self.zero = zero
            self.reserved1 = reserved1
            self.section_length = section_length
            self.program_number = program_number
            self.reserved2 = reserved2
            self.version_number = version_number
            self.current_next_indicator = current_next_indicator
            self.section_number = section_number
            self.last_section_number = last_section_number
            self.reserved3 = reserved3
            self.PCR_PID = PCR_PID
            self.reserved4 = reserved4
            self.program_info_length = program_info_length
            self.stream_type = stream_type
            self.reserved5 = reserved5
            self.elementary_PID = elementary_PID
            self.reserved6 = reserved6
            self.ES_info_length = ES_info_length
            self.CRC_32 = CRC_32
            self.PMT_Stream = []

        def list_all_member(self):
            for i, j in vars(self).items():
                print(i, ":  ", j)
    def make_struct(self,table_id=0x02,
                   section_syntax_indicator=0b1,
                   zero=0b0,
                   reserved1=0b11,
                   section_length=0x12,
                   program_number=0x0001,
                   reserved2=0x03,
                   version_number=0x00,
                   current_next_indicator=0x01,
                   section_number=0x00,
                   last_section_number=0x00,
                   reserved3=0x07,
                   PCR_PID=0x3e9,
                   reserved4=0x0f,
                   program_info_length=0x000,
                   stream_type=0x1b,
                   reserved5=0x07,
                   elementary_PID=0x3e9,
                   reserved6=0x0f,
                   ES_info_length=0x000,
                   CRC_32=0x0):
        return self.Struct(table_id,
                   section_syntax_indicator,
                   zero,
                   reserved1,
                   section_length,
                   program_number,
                   reserved2,
                   version_number,
                   current_next_indicator,
                   section_number,
                   last_section_number,
                   reserved3,
                   PCR_PID,
                   reserved4,
                   program_info_length,
                   stream_type,
                   reserved5,
                   elementary_PID,
                   reserved6,
                   ES_info_length,
                   CRC_32)

