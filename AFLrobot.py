#!/usr/bin/env python
# -*- coding: utf-8 -*-
import fuzzer
import logging
import json
import requests
import time
import urllib2
import angr
import shlex
import multiprocessing
import hashlib
from pwn import *
from fmt import FmtPayload
from stackoverflow_detect import StackOverflow

class AFLrobot:
    def __init__(self, cb, submit, user, password, afl_path, workdir='work', timeout=None):
        self.cb = cb
        self.cb_name = self.get_cb()
        self.crashes = []
        self.bin_md5 = self.get_bin_md5()
        # 读取已有的crash
        self.add_crashes_from_file()
        if self.crashes == []:
            seeds = self.get_possible_seed()
        if self.crashes == []:
            self.fuzzer = fuzzer.Fuzzer(
                self.cb_name, workdir, afl_path, seeds=seeds, time_limit=timeout)
            self.fuzzer_is_stop = False
        else:
            self.fuzzer_is_stop = True
            
            
        self.submit = submit
        self._user = user
        self._password = password
        # 必须有pid 建议不要起线程，直接起进程或者fork
        self.pid = None

    def add_crashes_from_file(self):
        try:
            crash_fp = open('work/'+ str(self.cb['ChallengeID']) + '_' +self.bin_md5 + '.crash', 'r')
        except IOError:
            return
        print('%d find crash text!' % self.cb['ChallengeID'])
        self.crashes.append(crash_fp.read())
        crash_fp.close()

    def get_bin_md5(self):
        '''get bin MD5'''
        fp = open(self.cb_name, 'rb')
        return hashlib.md5(fp.read()).hexdigest()

    def stop_fuzz(self):
        self.fuzzer_is_stop = True
        self.fuzzer.kill()
        self.write_crash_to_file()
        
    def write_crash_to_file(self):
        crash_fp = open('work/'+ str(self.cb['ChallengeID']) + '_' + self.bin_md5 + '.crash', 'w')
        crash_fp.write(self.crashes[0])
        crash_fp.close()

    def start(self):
        if self.crashes == []:
            self.fuzzer.start()
        proc = multiprocessing.Process(target=self._watch_process)
        proc.start()
        self.pid = proc.pid

    def terminate(self):
        if self.fuzzer_is_stop is False:
            self.fuzzer_is_stop = True
            self.fuzzer.kill()

    def is_alive(self):
        return not self.fuzzer_is_stop

    def get_crashes(self):
        return self.fuzzer.crashes()

    def submit_crash(self, bin_input):
        """submit the crash input to the specific url """
        contorl_eip = int(self.cb['EIP'], 16)
        memread_addr = int(self.cb['MemoryReadPath'],16)
        writemem_addr = int(self.cb['MemoryWritePath'],16)
        writemem_value = int(self.cb['MemoryWriteContent'],16)

        eip_payload = ''
        memread_payload = ''
        memwrite_payload = ''

        fmtp = FmtPayload(self.cb_name,bin_input)
        if fmtp.is_fmt():
            memwrite_payload = fmtp.get_write_payload(writemem_addr,writemem_value)
            memread_payload = fmtp.get_leak_payload(memread_addr)

        #else:
        #    p = StackOverflow('/tmp/', os.path.basename(self.cb_name), contorl_eip, 0xfffdd000, 0xffffe000)
        #    p.main_logic(bin_input, memread_addr, writemem_addr, writemem_value)
        #    eip_payload = p.eip_control_payload
        #    memread_payload = p.mem_read_payload
        #    memwrite_payload = p.mem_write_payload
            

        template = {"payloadInfo": [{
            "ChallengeID": "",
            "Payload": [
                {"Crash": ""},
                {"Eip": ""},
                {"Memwrite": ""},
                {"Memread": ""}],
            "Defense": ""}]}

        template["payloadInfo"][0]["ChallengeID"] = self.cb["ChallengeID"]
        template["payloadInfo"][0]["Payload"][0]["Crash"] = base64.b64encode(bin_input)
        template["payloadInfo"][0]["Payload"][0]["Eip"] = base64.b64encode(eip_payload)
        template["payloadInfo"][0]["Payload"][0]["Memwrite"] = base64.b64encode(memwrite_payload)
        template["payloadInfo"][0]["Payload"][0]["Memread"] = base64.b64encode(memread_payload)
        template["payloadInfo"][0]["Defense"] = base64.b64encode(self.get_defense(bin_input))
        
        print '\t{} Submitting crash'.format(self.cb['ChallengeID'])
        logging.info('{} Submitting crash'.format(self.cb['ChallengeID']))
        temstr = json.dumps(template["payloadInfo"])
        # the API checks for user agent
        headers = {'User-Agent': 'Mozilla/5.0'}
        ret = requests.post(self.submit, json=template, auth=(
            self._user, self._password), headers=headers)
        print '\t', str(self.cb['ChallengeID']), ret, ret.text
        logging.info('{} Submitting got ret_code {}, content:{}'.format(
            self.cb['ChallengeID'], ret, ret.text))

    def get_defense(self, crash_text):
        defense_file_path = 'work/'+ str(self.cb['ChallengeID']) + '_' +self.bin_md5 + '.defense'
        fp = open(defense_file_path, 'w')
        fp.write('a' * len(crash_text))
        fp.close()
        if self._is_seeds_crash(defense_file_path, self.cb_name):
            ret = '^.{0,%d}$' % len(crash_text)
            print('%d defense on' % self.cb['ChallengeID'])
        else:
            ret = ''
            print ('%d defense off' % self.cb['ChallengeID'])

        return ret


    def _watch_process(self):
        while self.fuzzer_is_stop is False:
            self.crashes += self.get_crashes()
            if len(self.crashes) > 0:
                self.stop_fuzz()
                break
            time.sleep(1)
        print('success')
        print(self.crashes)
        self.submit_crash(self.crashes[0])

    @staticmethod
    def get_terminal_width():
        """get the current width of the terminal

        :returns: list representing the number of rows and columns of the current terminal

        """
        cmd = shlex.split('stty size')
        process = subprocess.Popen(cmd, shell=False,
                                   stderr=subprocess.PIPE,
                                   stdout=subprocess.PIPE)
        size, _ = process.communicate()

        if size:
            try:
                return [int(i) for i in size.split()]
            except Exception as _:
                pass
        return [0, 50]

    def url_get_file(self, url, target_dir):
        """get file from an url

        :url: url of the file to be get
        :target_dir: path to the target file directory
        :returns: full path+name of the saved file

        """

        file_size_dl = 0
        block_sz = 8192

        req = urllib2.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        request = urllib2.urlopen(req)
        file_size = int(request.info().getheaders("Content-Length")[0])
        logging.info("{} Downloading:  [{}]".format(
            self.cb['ChallengeID'], url))
        logging.info("{} Size of file: [{}]".format(
            self.cb['ChallengeID'], file_size))
        file_name = '{}/{}_{}'.format(target_dir,
                                      self.cb['ChallengeID'], url.split('/')[-1])
        gz_file = open(file_name, 'wb')

        # print the progress
        status = ''
        bar_size = self.get_terminal_width()[1] / 2
        progress_size = 0
        blank_size = bar_size - progress_size
        os.system('setterm -cursor off')
        while True:
            buf = request.read(block_sz)
            if not buf:
                logging.info('{} Download Finished!'.format(
                    self.cb['ChallengeID']))
                break

            file_size_dl += len(buf)
            percentage = float(file_size_dl) / file_size
            gz_file.write(buf)

            progress_size = int(bar_size * percentage)
            blank_size = bar_size - progress_size

            status = "[{0}{1}] {2:d}/{3:d}   [{4:.2%}]"\
                .format('*' * progress_size,
                        ' ' * blank_size,
                        file_size_dl,
                        file_size,
                        percentage)

        os.system('setterm -cursor on')
        gz_file.close()

        return file_name

    def get_cb(self):
        """get the challenge binary """
        target_dir = '/tmp/'
        ret = self.url_get_file(self.cb['BinaryUrl'], target_dir)
        os.system('chmod +x ' + ret)
        return ret

    def get_possible_seed(self):
        ret = []

        ret.append(self._get_seeds('base_seed'))
        ret.append(self._get_seeds('number_seed'))
        ret.append(self._get_seeds('fmt_seed'))
        ret.append(self._get_seeds('symbols_seed'))

        return ret

    def _get_seeds(self, seed_name):
        seed_path = os.getcwd() + '/seeds/' + seed_name
        res = ''
        try:
            f = open(seed_path, 'rb')
            res = f.read()
            f.close()
        except Exception:
            print("seed " + seed_name + " not found !")
        if self._is_seeds_crash(seed_path, self.cb_name):
            self.crashes.append(res)
            print('%d seed crash' % (self.cb['ChallengeID']))
            self.write_crash_to_file()
                
        
        return res

    def _is_seeds_crash(self, seed, bin_path):
        try:
            proc = subprocess.Popen([bin_path], stdin=open(
                seed, 'rb'), stdout=subprocess.PIPE)
        except Exception:
            return False
        time.sleep(0.1)
        retcode = proc.poll()
        if retcode is None:
            proc.kill()
            return False
        if proc.returncode == -signal.SIGSEGV or proc.returncode == signal.SIGSEGV:
            return True
        if proc.returncode == -signal.SIGILL or proc.returncode == signal.SIGILL:
            return True
        return False
