import pyglet, imgui, logging
from imgui.integrations.pyglet import create_renderer
from pathlib import Path
from qiling import Qiling
from qiling.const import QL_ARCH
from qiling.utils import QilingColoredFormatter, FMT_STR
import capstone

# Regmaps
from qiling.arch.x86_const import reg_map_32 as x86_reg_map_32
from qiling.arch.x86_const import reg_map_64 as x86_reg_map_64
from qiling.arch.x86_const import reg_map_misc as x86_reg_map_misc
from qiling.arch.x86_const import reg_map_st as x86_reg_map_st
#from qiling.arch.arm_const import reg_map as arm_reg_map
#from qiling.arch.arm64_const import reg_map as arm64_reg_map
#from qiling.arch.mips_const import reg_map as mips_reg_map


SELF_PATH = Path(__file__).parent
SRC_PATH = SELF_PATH.parent.parent.parent
ROOTFS_PATH_32 = SRC_PATH / 'examples' / 'rootfs' / 'x86_windows'
ROOTFS_PATH_64 = SRC_PATH / 'examples' / 'rootfs' / 'x8664_windows'


SPEED_TEXT = ['0 ms', '50 ms', '100 ms', '300 ms', '1 s']
SPEED_VALUES = [0,     0.05,    0.1,     0.3,      1.0]


# pip install imgui[pyglet]
# https://www.aeracode.org/2018/02/19/python-async-simplified/

def get_reg_map(ql:Qiling):
    tables = {
        QL_ARCH.X86     : list({**x86_reg_map_32}.keys()),  #, **x86_reg_map_st
        QL_ARCH.X8664   : list({**x86_reg_map_64}.keys()),  #, **x86_reg_map_st
        #QL_ARCH.ARM     : list({**arm_reg_map}.keys()),
        #QL_ARCH.ARM64   : list({**arm64_reg_map}.keys()),
        #QL_ARCH.MIPS    : list({**mips_reg_map}.keys()),
    }

    return tables[ql.archtype]

def get_reg_map_misc(ql:Qiling):
    tables = {
        QL_ARCH.X86     : list({**x86_reg_map_misc}.keys()),  #, **x86_reg_map_st
        QL_ARCH.X8664   : list({**x86_reg_map_misc}.keys()),  #, **x86_reg_map_st
        #QL_ARCH.ARM     : list({**arm_reg_map}.keys()),
        #QL_ARCH.ARM64   : list({**arm64_reg_map}.keys()),
        #QL_ARCH.MIPS    : list({**mips_reg_map}.keys()),
    }

    return tables[ql.archtype]

def get_offset_and_name(ql, address):
    offset, name = ql.os.get_offset_and_name(address)
    if name == '[PE]':
        name = ql.targetname
    return offset, name

class LogWindow(logging.Handler):
    def __init__(self):
        super().__init__()
        self._msgs = []
        self._scroll_to_bottom = 0

    def on_logger_created(self, ql, logger):
        formatter = QilingColoredFormatter(ql, FMT_STR)
        self.setFormatter(formatter)
        logger.level = logging.DEBUG
        logger.handlers = []    # Remove the default console logger
        logger.addHandler(self)

    def emit(self, record):
        msg = self.format(record)
        msg = msg.replace('\033[9', '\033[3')   # pyimgui does not support the 'BRIGHT' colors
        self._msgs.append(msg)
        self._scroll_to_bottom = 2

    def clear(self):
        self._msgs = []

    def frame(self):
        imgui.set_next_window_position(10, 440, imgui.FIRST_USE_EVER)
        imgui.begin('Log')
        imgui.set_window_size(1000, 250, imgui.FIRST_USE_EVER)
        if imgui.button('Clear'):
            self._msgs = []
        imgui.separator()
        imgui.begin_child('scrolling', flags=imgui.WINDOW_ALWAYS_AUTO_RESIZE)
        imgui.push_style_var(imgui.STYLE_ITEM_SPACING, imgui.Vec2(0, 1))
        for line in self._msgs:
            imgui.text_ansi(line)
        if self._scroll_to_bottom > 0:
            self._scroll_to_bottom -= 1
            imgui.set_scroll_here(1.0)
        imgui.pop_style_var()
        imgui.end_child()
        imgui.end()

class Registers:
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

class DisasmView:
    def __init__(self):
        self.lines = []
        self.md = None
        self._addr_width = 0


    def capture(self, ql, address):
        if not self.md:
            self.md = ql.create_disassembler()
            self.md.detail = True   # Ask capstone to add instruction details
        self.lines = []
        if address:
            data = ql.mem.read(address, 200)
            decoded = self.md.disasm(data, address)
            bits = ql.archbit // 4
            #tmp = 
            #w = imgui.calc_text_size('%0*x' % (bits, 0))
            self._addr_width = bits * 10
            for insn in decoded:
                offset, name = get_offset_and_name(ql, insn.address)
                addr_name = '%s + 0x%03x' % (name, offset)

                addr = '%0*x' % (bits, insn.address)
                selected = address == insn.address

                data = ''
                for byte in insn.bytes:
                    data += ('%02x ' % byte)

                op_str = insn.op_str
                if len(insn.operands) == 1:
                    op = insn.operands[0]
                    if op.type == capstone.CS_OP_IMM:
                        offset, name = get_offset_and_name(ql, op.imm)
                        if name != '-':
                            op_str = '[%s + 0x%03x]' % (name, offset)
                    elif op.type == capstone.CS_OP_MEM:
                        mem = op.mem
                        if mem.base == 0 and mem.segment == 0 and mem.scale == 1:
                            assert op.size == 4, op.size
                            offset, name = get_offset_and_name(ql, mem.disp)
                            if name != '-':
                                op_str = 'dword ptr [%s + 0x%03x]' % (name, offset)

                insn_text = f'{insn.mnemonic} {op_str}'
                self.lines.append((addr, addr_name, selected, data, insn_text))

    def frame(self):
        imgui.set_next_window_position(240, 100, imgui.FIRST_USE_EVER)
        imgui.set_next_window_size(900, 300, imgui.FIRST_USE_EVER)
        imgui.begin('Disasm')
        imgui.columns(4)
        imgui.separator()
        width = self._addr_width
        for name in ('Address', 'Module Address', 'Bytes', 'Instruction'):
            imgui.text(name)
            if width:
                imgui.set_column_width(-1, width)
                width = 0
            imgui.next_column()
        imgui.separator()

        for addr, addr_name, selected, data, insn_text in self.lines:
            imgui.selectable(addr, selected, flags=imgui.SELECTABLE_SPAN_ALL_COLUMNS)
            imgui.calc_text_size('')
            imgui.next_column()

            imgui.text(addr_name)
            imgui.next_column()

            imgui.text(data)
            imgui.next_column()

            imgui.text(insn_text)
            imgui.next_column()

        imgui.columns(1)
        imgui.end()


class EmuObject:
    def __init__(self):
        self.log_window = LogWindow()
        self.registers = Registers()
        self.disasm = DisasmView()
        self.ql = None
        self._started = False
        self._speed = 3     # 300 ms
        self._dt = None
        self.init()

    def start_address(self):
        if self._started:
            return self.ql.reg.arch_pc
        elif self.ql.entry_point:
            return self.ql.entry_point
        else:
            return self.ql.loader.entry_point

    def exit_point(self):
        if not self._started and self.ql.entry_point:
            return self.ql.entry_point
        return self.ql.loader.entry_point


    def init(self):
        self.ql = Qiling([ROOTFS_PATH_32 / 'bin' /  'cmdln32.exe'],
                    ROOTFS_PATH_32,
                    libcache=True,
                    on_logger_created=self.log_window.on_logger_created)
        self._started = False
        self.capture()

    def capture(self):
        self.disasm.capture(self.ql, self.start_address())
        self.registers.capture(self.ql, self.start_address())

    def frame_fn(self, dt):
        if self._dt is not None:
            self._dt += dt
            if self._dt >= SPEED_VALUES[self._speed]:
                self.step()
                self._dt = 0.0


        self.control_window(dt)
        self.registers.frame()
        self.disasm.frame()
        self.log_window.frame()

        #imgui.set_next_window_collapsed(True, imgui.FIRST_USE_EVER)
        #imgui.show_demo_window()

    def step(self):
        if not self._started:
            self.ql.run(count=1)
            self._started = True
        else:
            self.ql.emu_start(self.start_address(), self.exit_point(), 0, 1)
        self.capture()


    def control_window(self, dt):
        imgui.set_next_window_position(10, 10, imgui.FIRST_USE_EVER)
        imgui.begin('Control', flags=imgui.WINDOW_ALWAYS_AUTO_RESIZE)

        if imgui.button(' Reset '):
            self.log_window.clear()
            self.init()
        imgui.same_line()
        if imgui.button(' > Step '):
            self.step()
        imgui.same_line()
        running = self._dt is not None
        run_text = ' [] Stop###StartStop' if running else ' >> Run ###StartStop'
        if imgui.button(run_text, ):
            if running:
                self._dt = None
            else:
                self._dt = 0.0
        imgui.same_line()
        _, self._speed = imgui.slider_int('', self._speed, 0, len(SPEED_VALUES) - 1, SPEED_TEXT[self._speed])
        imgui.end()



def run_window(update_fn):
    window = pyglet.window.Window(width=1280, height=720, resizable=True)
    imgui.create_context()
    io = imgui.get_io()
    io.ini_file_name = b''
    imgui.style_colors_dark()
    impl = create_renderer(window)

    def draw(dt):
        imgui.new_frame()
        update_fn(dt)   # Call the user supplied update callback

        window.clear()
        imgui.render()
        impl.render(imgui.get_draw_data())

    pyglet.clock.schedule_interval(draw, 1/120.)
    pyglet.app.run()
    impl.shutdown()

if __name__ == "__main__":
    emu = EmuObject()
    run_window(emu.frame_fn)
