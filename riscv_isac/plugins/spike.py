import re
from riscv_isac.log import logger
import riscv_isac.plugins as plugins
import riscv_isac.plugins.specification as spec
from riscv_isac.InstructionObject import instructionObject

class spike(spec.ParserSpec):

    @plugins.parserHookImpl
    def setup(self, trace, arch):
        self.trace = trace
        self.arch = arch

    instr_pattern_spike = re.compile(
        '[0-9]\s(?P<addr>[0-9abcdefx]+)\s\((?P<instr>[0-9abcdefx]+)\)')
    instr_pattern_spike_xd = re.compile(
        '[0-9]\s(?P<addr>[0-9abcdefx]+)\s\((?P<instr>[0-9abcdefx]+)\)' +
        '\s(?P<regt>[xf])(?P<reg>[\s|\d]\d)\s(?P<val>[0-9abcdefx]+)'
        )
    instr_pattern_spike_rvv = re.compile(
        '[0-9]\s(?P<addr>[0-9abcdefx]+)\s' +
            '\((?P<instr>[0-9abcdefx]+)\)\s'+
            '(c8_vstart\s[0-9abcdefx]+\s)?(e[0-9]+\sm[0-9]+\sl[0-9]+\s)?'+
            '(?P<regt>[xfv])(?P<reg>[\s|\d]?\d)\s+(?P<val>[0-9abcdefx]+)'
    )

    # instr_pattern_spike_rvv Match such as:
    # core   0: 0 {{0x00000000800001a8 (0x5e03d757) c8_vstart 0x0000000000000000 e32 m1 l1 v14 0x00000000000000000000000000000000}}
    # core   0: 0 {{0x000000008000019c (0x0200e287) e32 m1 l4 v5  0x00000000000000000000000000000000}} c8_vstart 0x0000000000000000 mem 0x0000000080004000 mem 0x0000000080004004 mem 0x0000000080004008 mem 0x000000008000400c
    # core   0: 0 {{0x000000008000029c (0xc100ffd7) x31 0x0000000000000001}} c8_vstart 0x0000000000000000 c3104_vl 0x0000000000000001


    def extractInstruction(self, line):
        instr_pattern = self.instr_pattern_spike
        re_search = instr_pattern.search(line)
        if re_search is not None:
            return int(re_search.group('instr'), 16), None
        else:
            return None, None

    def extractAddress(self, line):
        instr_pattern = self.instr_pattern_spike
        re_search = instr_pattern.search(line)
        if re_search is not None:
            return int(re_search.group('addr'), 16)
        else:
            return 0

    def extractRegisterCommitVal(self, line):

        instr_pattern = self.instr_pattern_spike_rvv
        re_search = instr_pattern.search(line)
        if re_search is not None:
            return (re_search.group('regt'), re_search.group('reg'), re_search.group('val'))
        else:
            return None

    @plugins.parserHookImpl
    def __iter__(self):
        with open(self.trace) as fp:
            for line in fp:
                logger.debug('parsing ' + str(line))
                instr, mnemonic = self.extractInstruction(line)
                addr = self.extractAddress(line)
                reg_commit = self.extractRegisterCommitVal(line)
                csr_commit = None
                instrObj = instructionObject(instr, 'None', addr, reg_commit = reg_commit, csr_commit = csr_commit, mnemonic = mnemonic )
                yield instrObj
