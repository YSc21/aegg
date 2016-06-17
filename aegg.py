from analyzer import Analyzer
from bug_finder import BugFinder
from exploiter import Exploiter
import logging
from verifier import Verifier

l = logging.getLogger("aegg.aegg")


class AEGG(object):
    def __init__(self, binary):
        if '/' not in binary:
            binary = './%s' % binary
            l.warning('Change binary name to %s' % binary)
        self.binary = binary
        self.payloads = []

        self.bug_finder = BugFinder(binary)
        self.analyzer = Analyzer(binary)
        self.exploiter = Exploiter()
        self.verifier = Verifier(binary)

    def _save(self, payload, file_name):
        with open(file_name, 'w') as f:
            f.write(payload)

    def exploit_gen(self, path):
        analysis = self.analyzer.analyze(path)
        for payload in self.exploiter.generate(path, analysis):
            if not payload:
                break
            if self.verifier.verify(payload):
                self.payloads.append(payload)
                l.info('Generated!')
                return True
        l.info('Can not generate any payload.')
        return False

    def hack(self, n=None, paths=None):
        """
        n: number paths want to check
        paths: angr path object
        """
        n = 1 if n is None else n
        paths = [] if paths is None else paths

        l.info('Start hacking ...')
        while len(paths) < n:
            found_paths = self.bug_finder.find()
            if found_paths is None:
                break
            paths.extend(found_paths)
        for path in paths:
            self.exploit_gen(path)
        l.info('Completed.')

    def save(self, file_name=None):
        file_name = self.binary if file_name is None else file_name
        if len(self.payloads) == 1:
            self._save(self.payloads[0], '%s.exp' % file_name)
        else:
            for i in xrange(len(self.payloads)):
                self._save(self.payloads[i], '%s-%d.exp' % (file_name, i))
