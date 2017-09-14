#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import os
import urllib2
import shlex
import subprocess
import random
import sys
import shutil
import time
import signal
import base64
import hashlib
import json
import requests
import multiprocessing
import logging
from datetime import datetime
import psutil
import fuzzer

FORMAT = '[%(levelname)s]\t%(asctime)s : %(message)s'
LOG_INFO = datetime.now().strftime('log_info_%Y_%m_%d_%H_%M.log')
logging.basicConfig(filename=LOG_INFO, level = logging.INFO, format=FORMAT)

round_timeout = 600  # timeout for each challenge round
subp_timeout = 60   # timeout for subprocess, used to kill infinite loop run in subprocess

robo_prefix = "dummy"

class Challenge(object):
    """Docstring for Challenge. """

    def __init__(self, url=None, user=None, password=None):
        """ init """

        self._url = url
        self._user = user
        self._password = password
        self.current_challenge = None
        self.current_round = None
        self.flow_packet = None
        self.points_info = None
        self.last_detail = None
        self.retjson = None


    def get_challenge(self):
        """ get the challenge info according to the url given """

        headers = {'User-Agent': 'Mozilla/5.0'}   # the API checks for user agent
        try:
            ret = requests.get(self._url, auth=(self._user, self._password), headers=headers).json()
            setattr(self, 'current_challenge', ret['CurrentChallenge'])
            setattr(self, 'current_round', ret['CurrentRound'])
            setattr(self, 'flow_packet', ret['FlowPacket'])
            setattr(self, 'points_info', ret['PointsInfo'])
            setattr(self, 'last_detail', ret['LastDetail'])
            setattr(self, 'retjson', str(ret))
            logging.info("The tick info:{}".format(self.retjson))
        except Exception as e:
            logging.error(str(e))
            return False

            
    def __repr__(self):
        return self.retjson

#######################################################################
""" Apply your own robo here """

class AFLRobo(object):
    """Docstring for AFLRobo. """

    #pylint: disable-msg=too-many-arguments
    def __init__(self, cb=None, submit=None, user=None, password=None,
                       aflpath=None, afloptions=None, cround=None):
        """ Constructor, initialize local variables """
        self.cb = cb
        self.submit = submit
        self._user = user
        self._password = password
        self.afl_path = aflpath
        self.afl_options = afloptions
        self.cround = cround
        self.cb_name = ''


    def worker(self):
        """launch afl"""
        cmd = self.afl_path
        cmd += ' -Q -i ./input -o . -M {}_cb_{} -m none -- '.format(self.cb['ChallengeID'], self.cround)
        cmd += self.cb_name
        logging.info(cmd)
        cmd_list = shlex.split(cmd)
        devnull = open(os.devnull, 'wb')
        proc = subprocess.Popen(cmd_list, shell=False, stdout=devnull, stderr=devnull)
        proc.communicate()


    def auto_fuzz(self):
        """fuzz """
        if not os.path.isfile(self.afl_path):
            print 'afl executable cannot be found'
            logging.error('afl executable cannot be found')
            exit(0)

        self.get_cb()
        proc1 = subprocess.Popen('chmod 755 {}'.format(self.cb_name), shell=True)
        proc1.communicate()
        proc = multiprocessing.Process(target=self.worker)
        proc.daemon = True
        proc.start()
        # watch for crash output directory (or watch for stats file?)
        stats_file = './{}_cb_{}/fuzzer_stats'.format(self.cb['ChallengeID'], self.cround)
        stats = dict()
        crashed = False
        while not crashed:
            # by default, fuzzer_stats updates every 60 seconds
            time.sleep(60)
            try:
                with open(stats_file, 'r') as fin:
                    for line in fin:
                        split = line.split()
                        stats[split[0]] = split[2]
            except Exception as e:
                logging.error(str(e))
                return -1
            if stats['last_crash'] != '0':
                crashed = True
        crash_dir = './{}_cb_{}/crashes'.format(self.cb['ChallengeID'], self.cround)
        for root, _, files in os.walk(crash_dir):
            for crash_file in files:
                if 'id' in crash_file:
                    self.submit_crash('{}/{}'.format(root, crash_file))
                    break
            break

    #######################################################################
    @staticmethod
    def calc_hash(fname):
        """calculate the md5 hash of a given file"""
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as fin:
            for chunk in iter(lambda: fin.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()


    def submit_crash(self, q_file):
        """submit the crash input to the specific url """
        logging.info(q_file)
        with open(q_file, 'rb') as fin:
            bin_input = fin.read()
            
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
        file_name = '{}/{}_{}_{}'.format(target_dir, robo_prefix, self.cb['ChallengeID'], url.split('/')[-1])
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
                #print '\n Download Finished!'
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
        """get the challenge binary and set attribute """
        target_dir = str(os.getcwd())
        self.cb_name = self.url_get_file(self.cb['BinaryUrl'], target_dir)

##############################################################################

#######################################################################
""" Apply your own robo here """

class DummyRobo(object):
    """Docstring for DummyRobo. """

    def __init__(self, cb=None, submit=None, user=None, password=None):
        """ Constructor, initialize local variables """
        self.cb = cb
        self._user = user
        self._password = password
        self.submit = submit
        self.infile = ''
        self.cb_name = ''
        self.payload = None

        # random seed
        self.seed = random.randint(0, sys.maxint)
        random.seed(self.seed)


    def input_gen(self, length, fname):
        """generate random input file given a specific length and file name

        :length: the length of the input to be generated
        :fname: the name of the file to be saved

        """
        with open(fname, 'wb') as fout:
            fout.write(os.urandom(length))
        self.infile = fname


    def auto_fuzz(self):
        """fuzz """
        crashed = False
        fname = '/tmp/{}_{}_cb_input'.format(robo_prefix, self.cb['ChallengeID'])
        self.get_cb()
        iteration = 0
        while not crashed:
            iteration += 1
            length = random.randint(1, 4096)
            self.input_gen(length, fname)
            crashed = self.execute()
            
            if crashed == True:
                logging.info('{} crashed at iteration {} with input seed {}'.format(self.cb['ChallengeID'], iteration, self.seed))
                logging.info('{} the input length is {}'.format(self.cb['ChallengeID'], length))
                self.submit_crash()
            
        return crashed, self.payload
                

    def execute(self):
        """execute the challenge binary with the random input and watch for possible crash

        """
        proc1 = subprocess.Popen('chmod 755 {}'.format(self.cb_name), shell=True)
        proc1.communicate()

        cmd = '{} < {}'.format(self.cb_name, self.infile)
        proc = subprocess.Popen(cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
        for t in xrange(subp_timeout):
            time.sleep(1)
            if proc.poll() is not None:
                proc.communicate()
                if proc.returncode == 139:
                    return True
                return False
                  
        proc.kill()   
        
        return False

    #######################################################################
    @staticmethod
    def calc_hash(fname):
        """calculate the md5 hash of a given file"""
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as fin:
            for chunk in iter(lambda: fin.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()


    def submit_crash(self):
        """submit the crash input to the specific url """
        with open(self.infile, 'rb') as fin:
            bin_input = fin.read()

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
        file_name = '{}/{}_{}_{}'.format(target_dir, robo_prefix, self.cb['ChallengeID'], url.split('/')[-1])
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
        self.cb_name = self.url_get_file(self.cb['BinaryUrl'], target_dir)

##############################################################################

def kill_child_proc(proc_pid):
    """kill all child proc by given proc_id"""
    try:
        proc = psutil.Process(proc_pid)
        for proc in process.get_children(recursive=True):
            print "{} kill child {}".format(proc_pid, proc.pid)
            logging.info("{} kill child {}".format(proc_pid, proc.pid))
            proc.kill()
        process.kill()  
    except Exception as e:
        logging.error(str(e))
        pass


def kill_by_cid(cid):
    """kill child process (used for zombie/run out of time)"""
    try:
        cmd_str = "{}_{}".format(robo_prefix, cid)
        for proc in psutil.process_iter():
            if cmd_str in proc.name():
                logging.info("{}: Found and kill zombie proc {}:{}".format(cid, proc.pid, proc.name()))
                proc.kill()
        
    except Exception as e:
        logging.error(str(e))
        pass


def check_alive(jobs):
    """check if there is any finished job
    if so, remove the record in dict:jobs
    """
    not_alive = []
    for cid in jobs:
        if not jobs[cid].is_alive():
            not_alive.append(cid)
    for naid in not_alive:
        del jobs[naid]

        
def del_all_jobs(jobs):
    """remove all jobs from joblist"""
    joblist = []
    for cid in jobs:
        joblist.append(cid)
    for jl in joblist:
        kill_child_proc(jobs[jl].pid)
        kill_by_cid(jl)
        jobs[jl].terminate()
        del jobs[jl]

        
def del_finished_jobs(jobs):
    """check and remove finished jobs from joblist"""
    joblist = []
    for cid in jobs:
        if jobs[cid].is_alive():
            pass
        else:
            joblist.append(cid)
    for jl in joblist:
        kill_child_proc(jobs[jl].pid)
        kill_by_cid(jl)
        jobs[jl].terminate()
        del jobs[jl]
        print "Remove finished job for {}".format(jl)

        
def del_a_job(jobs, cid):
    """remove a challenge job from joblist"""
    kill_child_proc(jobs[cid].pid)
    kill_by_cid(cid)
    jobs[cid].terminate()


def remove_inactive_jobs(jobs, cid_list):
    """remove inactive jobs from previous round"""
    out_of_time_list = []
    for cid in jobs:
        if cid not in cid_list:
            del_a_job(jobs, cid)
            logging.info("Remove jobs with inactive cid {}".format(cid))
            out_of_time_list.append(cid)
    for oot in out_of_time_list:
        del jobs[oot]


def print_round_info(tick):
    """print info for current round"""
    print "##### Starting New Round! #####"
    print "Current Round: {}".format(tick.current_round)
    print "Score Info: {}".format(tick.points_info)

    
def print_round_summary(jobs):
    """print summary for current round"""
    job_done = job_alive = 0
    for cid in jobs:
        if jobs[cid].is_alive():
            print "\tJob for {} is not finished".format(cid)
            job_alive += 1
        else:
            print "\tJob for {} is finished".format(cid)
            job_done += 1
    print "\t{}/{} job finished".format(str(job_done), str(job_done + job_alive))

################# Apply necessary changes to start your Robo #################

def parse_args():
    """parse arguments
    :returns: dictionary representing the parsed arguments

    """

    parser = argparse.ArgumentParser()
    parser.add_argument('--target', type=str, required=True)
    parser.add_argument('--submit', type=str, required=True)
    parser.add_argument('--team', type=str, required=True)
    parser.add_argument('--password', type=str, required=True)
    parser.add_argument('--robot', type=str)
    parser.add_argument('--aflpath', type=str)
    parser.add_argument('--afloptions', type=str)

    args = parser.parse_args()
    kwargs = vars(args)

    logging.info('\n\t##### A New Running #####')
    logging.info('The argvs are {}, {}, {}'.format(kwargs['target'], kwargs['submit'], kwargs['team']))
    return kwargs


def add_challenge_to_job(tick, jobs, cid_list, argv):
    """add new challenge into joblist
    Apply necessary changes to start your Robo
    """
    for challenge in tick.current_challenge:
        ccid = challenge['ChallengeID']
        cid_list.append(ccid)
        if ccid in jobs:
            logging.info('ccid {} already in jobs'.format(ccid))

        else:
            global robo_prefix
            # if argv['robot'] == 'afl':
            robo_prefix = "afl"
            # proc = multiprocessing.Process(target=robo_worker_afl, args=(challenge, argv, tick.current_round))
            proc = fuzzer.Fuzzer(challenge, "work")
            '''
            todo : select seeds for different challenge

            '''

            # else:
            #     robo_prefix = "dummy"
            #     proc = multiprocessing.Process(target=robo_worker, args=(challenge, argv))
            proc.deamon = True
            jobs[ccid] = proc
            proc.start()
            logging.info('ccid {} added to jobs'.format(ccid))


def robo_worker(challenge, argv):
    """target working function
    called by multiprocessing.Process
    """
    robot = DummyRobo(cb=challenge, submit=argv['submit'], user=argv['team'], password=argv['password'])
    robot.auto_fuzz()     # move to a new thread
    
    
def robo_worker_afl(challenge, argv, cround):
    """target working function
    called by multiprocessing.Process
    """
    robot = AFLRobo(cb=challenge,
                                submit=argv['submit'],
                                user=argv['team'],
                                password=argv['password'],
                                aflpath=argv['aflpath'],
                                afloptions=argv['afloptions'],
                                cround = cround)
    robot.auto_fuzz()     # move to a new thread

##############################################################################

def main():
    """ main function entry """
    # parse argument
    argv = parse_args()
    
    jobs = {} #dict to store {challenge_id|process_id}

    tick = Challenge(url=argv['target'], user=argv['team'], password=argv['password'])
    
    while True:

        # get challenge for the new round
        logging.info('\n\t*** A New Round of Challenge ! ***')
        
        if tick.get_challenge() is False:
            print "Error: No Challenge Found, Next Round"
            continue
        
        cid_list = [] # list of ids for current round challenge

        print_round_info(tick)
        
        # add current round challenge to jobs
        add_challenge_to_job(tick, jobs, cid_list, argv)

        # check and delete unactive challenge
        remove_inactive_jobs(jobs, cid_list)
        
        # sleep for the rest of the round
        time.sleep(round_timeout)
        
        # summary
        print_round_summary(jobs)
        
        # temporary job scheduling plan: stop all jobs&childs after a round
        for cid in jobs:
           kill_by_cid(cid) 
        
        #del_finished_jobs(jobs)
        del_all_jobs(jobs)

if __name__ == "__main__":
    main()
