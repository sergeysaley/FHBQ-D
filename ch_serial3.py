#!/usr/bin/env python3

import codecs 
import time
import serial 
import sys
from pprint import pprint

start_time = time.time()

s_port = '/dev/ttyUSB0'
b_rate = 9600
#open serial
SRL = serial.Serial(
    port=s_port,
    baudrate=b_rate,
    timeout=0.5
)

TRY = False
# print const
PRINT_CHECK     = True
PRINT_PREINFO   = False
PRINT_MASTER    = False
PRINT_PAST      = False
# return status const
# it's test read data
STATUS_READ_ERROR = True
# write serial const
MAX_SEND        = 21
# sniff const
MAX_TIME_SNIFF  = 180        # s
MAX_LINE_SNIFF  = 2700       # 1line = 0.067s

# verification and help lists 
class lists:
    list_helh = [
    "status       view current status",
    "n 1 auto     mode: normal; speed: 1; bypass: auto;",
    "n 2 auto     mode: normal; speed: 2; bypass: auto;",
    "n 3 auto     mode: normal; speed: 3; bypass: auto;",
    "n 1 on       mode: normal; speed: 1; bypass: on;",
    "n 2 on       mode: normal; speed: 2; bypass: on;",
    "n 3 on       mode: normal; speed: 3; bypass: on;",
    "n 1 off      mode: normal; speed: 1; bypass:  off;",
    "n 2 off      mode: normal; speed: 2; bypass: off;",
    "n 3 off      mode: normal; speed: 3; bypass: off;",
    "ne 1 auto    mode: normal exhaust; speed: 1; bypass: auto;",
    "ne 3 auto    mode: normal exhaust; speed: 3; bypass: auto;",
    "ne 1 on      mode: normal exhaust; speed: 1; bypass: on;",
    "ne 3 on      mode: normal exhaust; speed: 3; bypass: on;",
    "ne 1 off     mode: normal exhaust; speed: 1; bypass: off;",
    "ne 3 off     mode: normal exhaust; speed: 3; bypass: off;",
    "ns 1 auto    mode: normal supply; speed: 1; bypass: auto;",
    "ns 3 auto    mode: normal supply; speed: 3; bypass: auto;",
    "ns 1 on      mode: normal supply; speed: 1; bypass: on;",
    "ns 3 on      mode: normal supply; speed: 3; bypass: on;",
    "ns 1 off     mode: normal supply; speed: 1; bypass: off;",
    "ns 3 off     mode: normal supply; speed: 3; bypass: off;",
    "s 1 auto     mode: save; speed: 1; bypass: auto;",
    "s 2 auto     mode: save; speed: 2; bypass: auto;",
    "s 3 auto     mode: save; speed: 3; bypass: auto;",
    "s 1 on       mode: save; speed: 1; bypass: on;",
    "s 2 on       mode: save; speed: 2; bypass: on;",
    "s 3 on       mode: save; speed: 3; bypass: on;",
    "s 1 off      mode: save; speed: 1; bypass: off;",
    "s 2 off      mode: save; speed: 2; bypass: off;",
    "s 3 off      mode: save; speed: 3; bypass: off;",
    "se 1 auto    mode: save exhaust; speed: 1; bypass: auto;",
    "se 3 auto    mode: save exhaust; speed: 3; bypass: auto;",
    "se 1 on      mode: save exhaust; speed: 1; bypass: on;",
    "se 3 on      mode: save exhaust; speed: 3; bypass: on;",
    "se 1 off     mode: save exhaust; speed: 1; bypass: off;",
    "se 3 off     mode: save exhaust; speed: 3; bypass: off;",
    "ss 1 auto    mode: save supply; speed: 1; bypass: auto;",
    "ss 3 auto    mode: save supply; speed: 3; bypass: auto;",
    "ss 1 on      mode: save supply; speed: 1; bypass: on;",
    "ss 3 on      mode: save supply; speed: 3; bypass: on;",
    "ss 1 off     mode: save supply; speed: 1; bypass: off;",
    "ss 3 off     mode: save supply; speed: 3; bypass: off;",
    "off          turn off recuperator",
    "rhoff        turn off the relative humidity display",
    "rhon         turn on the relative humidity"
    ]

    com_valid=[
    "n1auto", "n2auto", "n3auto", "n1on", "n2on", "n3on", "n1off", "n2off", "n3off"]

#reading incoming bytes on serial
def read_serial(q):
    while True:
        data = SRL.read()
        if data == b'\x7e':
            data = data + SRL.read()       
            if data == b'\x7e\x7e':
                if     q == 'hex':
                    data = data + SRL.read(15)
                    return data
                else:
                    data = data + SRL.read(2) 
                    if     (q == 'revise' and data == b'\x7e\x7e\xc0\xff'):
                        data = data + SRL.read(13)
                        return data
                    if     (q == 'slave' and data == b'\x7e\x7e\x00\xa0'):
                        data = data + SRL.read(13)
                        return data
                    if     (q == 'master' and data == b'\x7e\x7e\xa0\x00'):
                        data = data + SRL.read(12)
                        return data
                

# converting bytes on serial to dic
def get_dic(data):
    dic = []
    for el in data:
        nel = hex(el)[2:4]
        nel = '0'+nel if len(nel) == 1 else nel
        dic.append(nel)
    return dic


def HexToByte(hexStr):
    bytes_a = []
    for i in range(0, len(hexStr), 2):
        bytes_a.append(chr(int(hexStr[i:i+2], 16)))
    return ''.join( bytes_a )
    
# getting checksum for packet hex 
def get_checksum(packet):
    checksum = 0
    for el in packet:
        checksum ^= ord(el)
    checksum = str(list(hex(checksum))[2]) + str(list(hex(checksum))[3])
    if PRINT_CHECK: print ('checksum = ' + checksum)
    return checksum

# checking sended
def checking_sended(send):
    while True:
        check = get_dic(read_serial('revise'))
        del check[16]
        
        if PRINT_MASTER: 
            master = get_dic(read_serial('master'))
            #del master[16]
            
        j = 4
        sum_check_byte = 0
        diff = []
        while j < 16:
            if check[j] == send[j]: 
                sum_check_byte += 1
            else: 
                diff.append(j)
            j += 1
        
        if PRINT_PREINFO:
            print ("sum_check_byte = ", sum_check_byte)
            print ("diff  = ", diff)
            print ("check = ", check)
            print ("send  = ", send)
        
        if sum_check_byte == 12: 
            if PRINT_PREINFO: print ('OK')
            ch_ret = 'OK'
        else: 
            if PRINT_PREINFO: print ("ERROR: something went wrong")
            ch_ret = 'ERROR'
        
        if PRINT_CHECK:
            print ('                                  bp sp      mode     ')
            j = 2
            str_sended = ''
            str_checking = ''
            str_master = ''
            while j < 16:
                if j in diff:
                    str_sended = str_sended + ' ' + str(send[j])
                    if ch_ret == 'OK':
                        str_checking = str_checking + ' ' + str(check[j])
                    if ch_ret == 'ERROR':
                        str_checking = str_checking + ' ' + str(check[j])
                elif j == 3:
                    str_sended = str_sended + ' ' + str(send[j]) + ' ->'
                    str_checking = str_checking + ' ' + str(check[j]) + ' ->'
                    if PRINT_MASTER: str_master = str_master + ' ' + str(master[j]) + ' ->'
                else:
                    str_sended = str_sended + ' ' + str(send[j])
                    str_checking = str_checking + ' ' + str(check[j])
                    if PRINT_MASTER: str_master = str_master + ' ' + str(master[j])
                j += 1
            print ('sended:  ' + str_sended)
            if PRINT_MASTER: print ('master:  ' + str_master)
            print ('checking:' + str_checking)
            
            if PRINT_PAST:
                i=1
                while i <= 3:
                    print ('       ' + ' '.join(get_dic(read_serial('hex'))))
                    i += 1
        
        return ch_ret

#reading current status for output
def read_status():
    status = ''
    
    if STATUS_READ_ERROR:
        rx = get_dic(read_serial('master'))
        if rx[14] == '8f': 
            err = 'error: need cleaning;'
        else: 
            err = 'error: ' + str(rx[14]) + '; '
        status = status + err
    
    while True:
        rx = get_dic(read_serial('revise'))

        if (rx[9] == '0a' or rx[9] == '2a' or rx[9] == '4a'   or rx[9] == '07' or rx[9] == '27' or rx[9] == '47'):
            status = 'off'
            break
        else:
            bypass = 'undefined'
            if (rx[9] == '8e'): bypass = 'bypass: auto; '
            if (rx[9] == 'ae'): bypass = 'bypass: on; '
            if (rx[9] == 'ce'): bypass = 'bypass: off; '
            if (rx[13] == '00' or rx[13] == '20'):
                if rx[10] == '0c': mode = 'mode: normal; speed: 1; '
                if rx[10] == '12': mode = 'mode: normal; speed: 2; '
                if rx[10] == '21': mode = 'mode: normal; speed: 3; '
        status = mode + bypass + status
        break
    
    if PRINT_CHECK: print (" %s seconds  " % (time.time() - start_time))
    return status

#runing command
def run_com(cm):
    while True:
        if cm[0] == 'h':
            com = cm[1]
            rx = []
            for i in range(len(com)//2):
                if i == 0:
                    rx.append(com[0] + com[1])
                if i > 0: 
                    rx.append(com[i*2] + com[i*2+1])

        else:
            rx = get_dic(read_serial('revise'))
            rx[2] = '00'
            rx[3] = 'a0'
            if cm[0] == 'off': 
                if rx[9] == '8e': rx[9] = '0e'
                if rx[9] == 'ae': rx[9] = '2e'
                if rx[9] == 'ce': rx[9] = '4e'
            else:
                if (cm[2] == 'auto' and rx[9] == '0e'): rx[9] = '8e'        #'bypass: auto; '
                if (cm[2] == 'on' and rx[9] == '2e'):   rx[9] = 'ae'        #'bypass: on; '
                if (cm[2] == 'off' and rx[9] == '4e'):  rx[9] = 'ce'        #'bypass: off; '

                if (cm[0] == 'n'):
                    rx[13] = '20'
                    if (cm[0] == 'n' and cm[1] == '1'): rx[10] = '0c'         #'mode: normal; speed: 1; '
                    if (cm[0] == 'n' and cm[1] == '2'): rx[10] = '12'         #'mode: normal; speed: 2; '
                    if (cm[0] == 'n' and cm[1] == '3'): rx[10] = '21'         #'mode: normal; speed: 3; '        
        del rx[16]
        
        packet = HexToByte(''.join(rx))
        checksum = get_checksum(packet)
        
        com = ''.join(rx)+checksum
        if PRINT_CHECK: print ('com = ' + com)
        
        answer = ''
        i = 1
        while answer != 'OK':
            if TRY:
                if   ((i+2)%3 == 0): tlg = 'slave'
                elif ((i+1)%3 == 0): tlg = 'master'
                elif (i%3 == 0):     tlg = 'revise'
            else: tlg = 'slave'
            read_serial(tlg)
            if (PRINT_CHECK and TRY): 
                print ()
                print ('after of = ' + tlg)
            if i > MAX_SEND: 
                break
            SRL.write(codecs.decode(com, 'hex_codec'))
            answer = checking_sended(rx)
            i += 1
                    
        if PRINT_CHECK: print (str(i-1) + ' attempts of send '+ " %s seconds  " % (time.time() - start_time))
            
        break
        
    if PRINT_PREINFO:  print ('current status: ' + read_status())
    if answer != "OK": print ('ERROR')
    if answer == "OK": print ('DONE')
    sys.exit()
    
def main():
    if len(sys.argv) == 2:
        if sys.argv[1] == 'status':
            #print (read_status())
            print (read_status())
            sys.exit()
        if sys.argv[1] == 'sniff_b':
            i = 1
            st = time.time() 
            while i <= MAX_LINE_SNIFF or (time.time() - start_time) > MAX_TIME_SNIFF:
                if i % 3 == 0: 
                    print (time.time() - st)
                    st = time.time() 
                    print ()
                print (' '.join(get_dic(read_serial('hex'))))
                i += 1
        if sys.argv[1] == 'sniff':
            i = 1
            st = time.time() 
            while i <= MAX_LINE_SNIFF or (time.time() - start_time) > MAX_TIME_SNIFF:
                print (' '.join(get_dic(read_serial('slave'))))
                print (' '.join(get_dic(read_serial('master'))))
                print (' '.join(get_dic(read_serial('revise'))))
                print (time.time() - st)
                st = time.time() 
                print ()
                i += 1
        if (sys.argv[1] == 'off'):
            run_com([sys.argv[1], ' ', ' '])
            sys.exit()
        if sys.argv[1] == 'help':
            print ('posiple/valid command: ')
            for p in lists.list_helh: print (p)
            sys.exit()
    elif len(sys.argv) == 3:
        if sys.argv[1] == 'h':
            if len(sys.argv[2]) == 34: 
                cm = [sys.argv[1], sys.argv[2]]
                run_com(cm)
            else:
                print ("ERROR: Your command is not valid")
                sys.exit()
    elif len(sys.argv) == 4:
        cm = [sys.argv[1], sys.argv[2], sys.argv[3]]
        if ''.join(cm) in lists.com_valid:
            run_com(cm)
        else:
            print ("ERROR: Your command is not valid, see help")
            sys.exit()
    else:
        print ("ERROR: Your command is not valid, see help")
        sys.exit()

main()
