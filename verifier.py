import commands
import logging
from pwn import *

l = logging.getLogger("aegg.verifier")


class Verifier(object):
    TEST_CMDS = ['uname -a', 'id', 'whoami']

    def __init__(self, binary):
        if '/' not in binary:
            binary = './%s' % binary
            l.warning('Change binary name to %s' % binary)
        self.binary = binary
        self.delay = 0.5

    def _verify(self, payload, cmd):
        l.info('Verifying by cmd: %s ...' % cmd)
        s = process(self.binary)

        s.sendline(payload)
        s.recvrepeat(self.delay)
        s.sendline(cmd)
        recv = s.recvrepeat(self.delay)
        s.close()

        uname = commands.getoutput(cmd)
        if uname in recv:
            l.info('... succeeded!')
            return True
        l.info('... failed!')
        return False

    def verify(self, payload):
        for cmd in Verifier.TEST_CMDS:
            if self._verify(payload, cmd):
                return True
        return False
