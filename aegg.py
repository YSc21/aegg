from analyzer import Analyzer
from bug_finder import BugFinder
import logging
from verifier import Verifier

l = logging.getLogger("aegg.aegg")


class AEGG(object):
    def __init__(self, binary):
        self.binary = binary
        self.payloads = []

    def hunt(self):
        l.info('Start hunting ...')
