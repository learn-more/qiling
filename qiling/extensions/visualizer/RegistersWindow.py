import imgui
from qiling.const import QL_ARCH

# Regmaps
from qiling.arch.x86_const import reg_map_32 as x86_reg_map_32
from qiling.arch.x86_const import reg_map_64 as x86_reg_map_64
from qiling.arch.x86_const import reg_map_misc as x86_reg_map_misc
from qiling.arch.x86_const import reg_map_st as x86_reg_map_st


def get_reg_map(ql):
    tables = {
        QL_ARCH.X86     : list({**x86_reg_map_32}.keys()),  #, **x86_reg_map_st
        QL_ARCH.X8664   : list({**x86_reg_map_64}.keys()),  #, **x86_reg_map_st
    }

    return tables[ql.archtype]

def get_reg_map_misc(ql):
    tables = {
        QL_ARCH.X86     : list({**x86_reg_map_misc}.keys()),  #, **x86_reg_map_st
        QL_ARCH.X8664   : list({**x86_reg_map_misc}.keys()),  #, **x86_reg_map_st
    }

    return tables[ql.archtype]

class RegistersWindow:
    def __init__(self):
        # Missing in ql.reg.bit:
        self._bits = {
            'ef': 32 // 4,
            'cs': 16 // 4, 'ss': 16 // 4,
            'ds': 16 // 4, 'es': 16 // 4,
            'fs': 16 // 4, 'gs': 16 // 4,
        }
        self._regs = []
        self._old = {}

    def _bit(self, ql, reg):
        if not reg in self._bits:
            bitval = ql.reg.bit(reg)
            assert bitval is not None, reg
            # Cache the result, since ql.reg.bit has ~20 indirections
            self._bits[reg] = bitval // 4
        return self._bits[reg]

    def capture(self, ql, address):
        if not ql:
            return
        self._regs = []
        regs = get_reg_map(ql)
        for reg in regs:
            self._regs.append(self._one_reg(ql, reg, '%-3s  %s%0*x'))

        full_map = get_reg_map_misc(ql)
        if not full_map:
            return

        regs = [reg for reg in full_map if reg != 'ef']
        self._regs.append('-sep-')
        if 'ef' in full_map:
            self._regs.append(self._one_reg(ql, 'ef', '%-3s  %s%0*x'))
            self._regs.append('-sep-')

        for idx, reg in enumerate(regs):
            if idx % 2 == 1:
                self._regs.append('-same-')
            self._regs.append(self._one_reg(ql, reg, '%s %s%0*x'))

    def _one_reg(self, ql, reg, fmt):
        val = ql.reg.read(reg)
        bits = self._bit(ql, reg)
        color = '\033[0m'
        if val != self._old.get(reg, val):
            color = '\033[31m'
        self._old[reg] = val
        return fmt % (reg, color, bits, val)

    def frame(self):
        imgui.set_next_window_position(10, 100, imgui.FIRST_USE_EVER)
        imgui.begin('Registers', flags=imgui.WINDOW_ALWAYS_AUTO_RESIZE)
        for line in self._regs:
            if line == '-same-':
                imgui.same_line()
            elif line == '-sep-':
                imgui.separator()
            else:
                imgui.text_ansi(line)
        imgui.end()
