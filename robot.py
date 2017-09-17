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
from AFLrobot import *
#import AFLroboot

FORMAT = '[%(levelname)s]\t%(asctime)s : %(message)s'
LOG_INFO = datetime.now().strftime('log_info_%Y_%m_%d_%H_%M.log')
logging.basicConfig(filename=LOG_INFO, level = logging.INFO, format=FORMAT)

round_timeout = 600  # timeout for each challenge round
#round_timeout = 20  # timeout for each challenge round
subp_timeout = 60   # timeout for subprocess, used to kill infinite loop run in subprocess


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

def kill_child_proc(proc_pid):
    """kill all child proc by given proc_id"""
    try:
        process = psutil.Process(proc_pid)
        for proc in process.children(recursive=True):
            print "{} kill child {}".format(proc_pid, proc.pid)
            logging.info("{} kill child {}".format(proc_pid, proc.pid))
            proc.kill()
        process.kill()  
    except Exception as e:
        logging.error(str(e))
        pass


def kill_by_cid(cid):
    """kill child process (used for zombie/run out of time)
    需要确保bin的文件名包含cid 否则该函数不起作用"""
    try:
        cmd_str = "{}".format(cid)
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
        #if str(ccid) != '71':
            #continue
        cid_list.append(ccid)
        if ccid in jobs:
            logging.info('ccid {} already in jobs'.format(ccid))

        else:
            # 开始工作
            proc = AFLrobot(challenge, argv['submit'], argv['team'], argv['password'], workdir="work")
            jobs[ccid] = proc
            proc.start()
            logging.info('ccid {} added to jobs'.format(ccid))



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
