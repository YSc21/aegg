import commands
import logging
from pwn import *

l = logging.getLogger("aegg.verifier")


class Verifier(object):
    CMDS = ['uname -a', 'id', 'man']

    def __init__(self, binary):
        self.binary = binary
        self.delay = 0.5

    def _is_contain(self, r, result):
        if r in result:
            l.info('... succeeded!')
            return True
        l.info('... failed!')
        return False

    def _verify_string(self, content, cmd):
        l.info('Verifying by cmd: %s ...' % cmd)
        s = process(self.binary)

        s.sendline(content)
        s.recvrepeat(self.delay)
        s.sendline(cmd)
        result = s.recvrepeat(self.delay)
        s.close()

        cmd_result = commands.getoutput(cmd)
        return self._is_contain(cmd_result, result)

    def _verify_script(self, content, cmd):
        with open('verify.tmp', 'w') as f:
            f.write(content)
        result = commands.getoutput('python verify.tmp "%s"' % cmd)
        cmd_result = commands.getoutput(cmd)
        return self._is_contain(cmd_result, result)

    def verify(self, payload):
        for cmd in Verifier.CMDS:
            try:
                if (payload.ptype == 'string' and
                        self._verify_string(payload.content, cmd)):
                    return True
                elif (payload.ptype == 'script' and
                        self._verify_script(payload.content, cmd)):
                    return True
            except Exception, e:
                l.warning('Pwnlib Error: %s %s' % (Exception, e))
        l.info('All cmds failed.')
        return False
