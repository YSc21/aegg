from error import *
import logging

l = logging.getLogger("aegg.analyzer")


class Analyzer(object):
    MIN_BUF_SIZE = 20

    def __init__(self):
        self.paths = []
        self.results = []

    def _new_result(self):
        return {
            'arch': '',
            'ip_symbolic': False,
            'ip_controled_name': '',
            'bufs': [],
        }

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

    def _get_bufs(self, state):
        # TODO: check more simfiles
        stdin_file = state.posix.get_file(0)

        sym_addrs = []
        for var in stdin_file.variables():
            sym_addrs.extend(state.memory.addrs_for_name(var))

        bufs = []
        for addr in sym_addrs:
            addr, length = self._check_continuity(addr, sym_addrs)
            if length >= Analyzer.MIN_BUF_SIZE:
                bufs.append({'addr': addr, 'length': length})
        return bufs

    def _analyze(self, path):
        result = self._new_result()
        state = path.state
        result['arch'] = state.arch.name
        result['ip_symbolic'] = self._fully_symbolic(state, state.ip)
        l.debug('Checking ip %s... symbolic: %s' %
                (str(state.ip)[:50], result['ip_symbolic']))
        if result['ip_symbolic']:
            if state.ip.op == 'Extract':
                result['ip_controled_name'] = state.ip.args[2].args[0]
            else:
                l.warning('ip: %s..., ip.op != "extract"' % str(state.ip)[:50])
            result['bufs'] = self._get_bufs(state)
            l.debug('Finding %d buffers.' % len(result['bufs']))
        return result

    def analyze(self, path):
        result = self._analyze(path)
        self.paths.append(path)
        self.results.append(result)
        return result
