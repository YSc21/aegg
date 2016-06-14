import angr
import logging
from simuvex import s_options as o

angr.simuvex.l.setLevel('CRITICAL')
l = logging.getLogger("aegg.bug_finder")


class BugFinder(object):
    def __init__(self, binary, executor=None):
        self.binary = binary
        self.paths = []

        self.pg = self._init_pg()

    def _init_pg(self):
        p = angr.Project(self.binary)
        extras = {o.REVERSE_MEMORY_NAME_MAP, o.TRACK_ACTION_HISTORY}
        state = p.factory.full_init_state(add_options=extras)
        state.libc.buf_symbolic_bytes = 200
        pg = p.factory.path_group(state, save_unconstrained=True)
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
