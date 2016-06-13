import logging

l = logging.getLogger("aegg.analyzer")


class Analyzer(object):
    def __init__(self):
        self.paths = []
        self.payloads = []

    def analyze(self, path):
        self.paths.append(path)
