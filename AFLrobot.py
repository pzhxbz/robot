#!/usr/bin/env python
# -*- coding: utf-8 -*-
import fuzzer



class AFLrobot:
    def __init__(self, path, workdir = 'work'):
        '''
        todo : select seeds for different challenge

        '''
        self.fuzzer = fuzzer.Fuzzer(path,work)
    
    def kill(self):
        self.fuzzer.kill()

    def start(self):
        self.fuzzer.start()
    
    def terminate(self):
        self.fuzzer.kill()

    def is_alive(self):
        return self.fuzzer.alive()

    def get_crashes(self):
        return self.fuzzer.crashes()