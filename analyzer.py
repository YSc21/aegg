import logging
from pwn import ELF
from pwn import p32
from pwn import p64
import random

l = logging.getLogger("aegg.analyzer")


class Analyzer(object):
    MIN_BUF_SIZE = 20

    def __init__(self, binary):
        self.binary = binary
        self.path = None
        self.result = None
        self.paths = []
        self.results = []

    def _new_result(self):
        return {
            'arch': '',
            'ip_symbolic': False,
            'ip_vars': [],
            'padding': -1,
            'bufs': [],
            'elf': {},
        }

    def _get_padding(self):
        state = self.path.state

        if state.ip.op == 'Extract':
            return state.ip.args[1] / 8
        else:
            l.warning('ip: %s..., ip.op != "extract"' % str(state.ip)[:50])
            padding = set()
            for _ in xrange(5):
                test_value = random.getrandbits(state.arch.bits)
                tmp = self.path.copy()
                tmp.state.add_constraints(tmp.state.ip == test_value)
                inp = tmp.state.posix.dumps(0)
                if state.arch.bits == 32:
                    padding.add(inp.find(p32(test_value)))
                else:
                    padding.add(inp.find(p64(test_value)))
            if len(padding) != 1:
                l.warning('Found multiple paddings: %s' % padding)
            return padding.pop()

    def _fully_symbolic(self, state, variable):
        for i in range(state.arch.bits):
            if not state.se.symbolic(variable[i]):
                return False
        return True

    def _check_continuity(self, address, all_address):
        i = 0
        while True:
            if not address + i in all_address:
                return address, i
            i += 1

    def _get_bufs(self):
        state = self.path.state
        # TODO: check more simfiles
        stdin_file = state.posix.get_file(0)

        sym_addrs = []
        for var in stdin_file.variables():
            sym_addrs.extend(state.memory.addrs_for_name(var))
        sym_addrs = sorted(sym_addrs)

        bufs = []
        for addr in sym_addrs:
            addr, length = self._check_continuity(addr, sym_addrs)
            if length >= Analyzer.MIN_BUF_SIZE:
                bufs.append({'addr': addr, 'length': length})
        return bufs

    def _binary_info(self):
        """
        pwntools source:
            https://github.com/Gallopsled/pwntools/blob/master/pwnlib/elf/__init__.py#L652

        RELRO:
            - 'Full'
            - 'Partial'
            - None
        Stack Canary:
            - True
            - False
        NX:
            - True
            - False
        PIE:
            - True
            - False
        """
        elf = ELF(self.binary)
        self.result['elf'] = {
            'RELRO': elf.relro,
            'Canary': elf.canary,
            'NX': elf.nx,
            'PIE': elf.pie}

    def _ip_symbolic_info(self):
        state = self.path.state

        self.result['ip_vars'] = list(state.ip.variables)
        self.result['padding'] = self._get_padding()
        self.result['bufs'] = self._get_bufs()
        l.debug('Finding %d buffers.' % len(self.result['bufs']))

    def _analyze(self):
        state = self.path.state

        self._binary_info()
        self.result['arch'] = state.arch.name
        self.result['ip_symbolic'] = self._fully_symbolic(state, state.ip)

        l.debug('Checking ip %s... symbolic: %s' %
                (str(state.ip)[:50], self.result['ip_symbolic']))
        if self.result['ip_symbolic']:
            self._ip_symbolic_info()

    def analyze(self, path):
        self.path = path
        self.result = self._new_result()
        self._analyze()

        self.paths.append(self.path)
        self.results.append(self.result)
        import IPython
        shell = IPython.terminal.embed.InteractiveShellEmbed()
        shell.mainloop(display_banner="\nDebug time!")
        exit()
        return self.result
