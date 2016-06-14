import logging
from pwn import *

l = logging.getLogger("aegg.verifier")


class Verifier(object):
    def __init__(self, binary):
        self.binary = binary

    def verify(self, payload):
        pass
