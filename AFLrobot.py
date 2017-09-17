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
from pwn import *


afl_path = '/home/cnss/Desktop/afl'

class AFLrobot:
    def __init__(self, cb, submit, user, password, workdir='work', timeout=None, debug=False):
        self.cb = cb
        if debug == True:
            self.cb_name = os.getcwd() + '/test/test'
        else:
            self.cb_name = self.get_cb()
        self.crash_seed = []
        seeds = self.get_possible_seed()
        self.fuzzer = fuzzer.Fuzzer(self.cb_name, workdir, afl_path, seeds = seeds, time_limit=timeout)
        self.is_stop = False
        self.submit = submit
        self._user = user
        self._password = password
        # 必须有pid 建议不要起线程，直接起进程或者fork
        self.pid = None
        

    def stop_fuzz(self):
        self.is_stop = True
        self.fuzzer.kill()


    def start(self):
        self.fuzzer.start()
        proc = multiprocessing.Process(target=self._watch_process)
        proc.start()
        self.pid = proc.pid

        #thread.start_new_thread(self._watch_process,())

    
    def terminate(self):
        self.is_stop = True
        self.fuzzer.kill()


    def is_alive(self):
        return self.fuzzer.alive

    def get_crashes(self):
        return self.fuzzer.crashes()

    def submit_crash(self, bin_input):
        """submit the crash input to the specific url """
            
        template = {"payloadInfo":[{
            "ChallengeID": "",
            "Payload": [
                {"Crash": ""},
                {"Eip": ""},
                {"Memwrite": ""},
                {"Memread": ""}],
            "Defense": ""}]}

        template["payloadInfo"][0]["ChallengeID"] = self.cb["ChallengeID"]
        template["payloadInfo"][0]["Payload"][0]["Crash"] = base64.b64encode(bin_input)
        print '\t{} Submitting crash'.format(self.cb['ChallengeID'])
        logging.info('{} Submitting crash'.format(self.cb['ChallengeID']))
        temstr = json.dumps(template["payloadInfo"])
        headers = {'User-Agent': 'Mozilla/5.0'}   # the API checks for user agent
        ret = requests.post(self.submit, json = template, auth=(self._user, self._password), headers=headers)
        print '\t', str(self.cb['ChallengeID']), ret, ret.text
        logging.info('{} Submitting got ret_code {}, content:{}'.format(self.cb['ChallengeID'], ret, ret.text))

    def _watch_process(self):
        if len(self.crash_seed) > 0:
            print('seed crash')
	    self.submit_crash(self.crash_seed[0])
	    self.stop_fuzz()
            return
        while not self.is_stop:
            time.sleep(1)
            crashes = self.get_crashes()
            if len(crashes) == 0:
                continue
            for crash in crashes:
                print 'success'
                self.submit_crash(crash[0])
                #print crash
            break
        self.stop_fuzz()


    
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
        logging.info("{} Downloading:  [{}]".format(self.cb['ChallengeID'], url))
        logging.info("{} Size of file: [{}]".format(self.cb['ChallengeID'], file_size))
        file_name = '{}/{}_{}'.format(target_dir, self.cb['ChallengeID'], url.split('/')[-1])
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
                logging.info('{} Download Finished!'.format(self.cb['ChallengeID']))
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
        '''未完成'''
        self.project = angr.Project(self.cb_name)
        self.elf = ELF(self.cb_name)
        ret = []

        ret.append(self._get_seeds('base_seed'))
	ret.append(self._get_seeds('number_seed'))
	
        # has import printf
        if self.elf.symbols.has_key('printf'):
            ret.append(self._get_seeds('fmt_seed'))
        
        '''
        todo : 
        '''
	
        return ret

    def _get_seeds(self, seed_name):
        seed_path = os.getcwd()+'/seeds/'+seed_name
        try:
            f = open(seed_path,'rb')
            res = f.read()
            f.close()
            if self._is_seeds_crash(seed_path,self.cb_name):
		self.crash_seed.append(res)
        except Exception:
            print("seed "+seed_name+" not found !" )
        return res

    def _is_seeds_crash(self,seed,bin_path):
        try:
            proc = subprocess.Popen([bin_path], stdin=open(seed,'rb'), stdout = subprocess.PIPE)
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
