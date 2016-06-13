import angr
import logging

l = logging.getLogger("aegg.bug_finder")


class BugFinder(object):
    def __init__(self, binary):
        self.binary = binary
