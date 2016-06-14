import angr
import logging

angr.simuvex.l.setLevel('CRITICAL')
l = logging.getLogger("aegg.bug_finder")


class BugFinder(object):
    def __init__(self, binary, executor=None):
        self.binary = binary
        self.paths = []

        self.pg = self._init_pg()

    def _init_pg(self):
        p = angr.Project(self.binary)
        state = p.factory.entry_state()
        state.libc.buf_symbolic_bytes = 200
        pg = p.factory.path_group(state,
                                  immutable=False, save_unconstrained=True)
        return pg

    def find(self):
        """ return a list of paths """
        self.pg.step(until=lambda pg: len(pg.unconstrained) > 0)
        if len(self.pg.unconstrained) > 0:
            paths = self.pg.unconstrained
            self.pg.move('unconstrained', 'checked')
            return paths
        return None

    def get_all_paths(self):
        return self.pg.checked
