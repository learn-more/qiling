import pyglet, imgui
from imgui.integrations.pyglet import create_renderer
from qiling import Qiling

from qiling.extensions.visualizer.DisasmWindow import DisasmWindow
from qiling.extensions.visualizer.LogWindow import LogWindow
from qiling.extensions.visualizer.RegistersWindow import RegistersWindow
from qiling.extensions.visualizer.SelectBinaryWindow import SelectBinaryWindow



SPEED_TEXT = ['0 ms', '50 ms', '100 ms', '300 ms', '1 s']
SPEED_VALUES = [0,     0.05,    0.1,     0.3,      1.0]

# pip install imgui[pyglet]
# https://www.aeracode.org/2018/02/19/python-async-simplified/



class QilingView:
    def __init__(self):
        self.log = LogWindow()
        self.registers = RegistersWindow()
        self.disasm = DisasmWindow()
        self.select_bin = SelectBinaryWindow()
        self.ql = None
        self._started = False
        self._speed = 3     # 300 ms
        self._dt = None
        self._argv = None
        self._rootfs = None
        self._output = None

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

    def close(self):
        self._dt = None
        self._started = False
        self.disasm.reset()
        self.log.reset()
        self.ql = None

    def init(self):
        self._dt = None
        self._started = False
        self.disasm.reset()
        self.log.reset()
        self.ql = Qiling(self._argv,
                    self._rootfs,
                    libcache=True,
                    output=self._output,
                    log_override=self.log.create_logger())
        # Now process stuff logged during creation:
        self.log.set_ql(self.ql)
        self.capture_state()

    def capture_state(self):
        self.disasm.capture(self.ql, self.start_address())
        self.registers.capture(self.ql, self.start_address())

    def frame(self, dt):
        if not self.ql:
            res = self.select_bin.frame()
            if not res:
                return
            # We got a binary, initialize it!
            self._argv, self._rootfs, self._output = res
            self.init()
            return

        # Auto-stepping
        if self._dt is not None:
            self._dt += dt
            if self._dt >= SPEED_VALUES[self._speed]:
                self._dt = 0.0
                self.step()

        self.control_window_frame(dt)
        self.disasm.frame()
        self.registers.frame()
        self.log.frame()

        #imgui.set_next_window_collapsed(True, imgui.FIRST_USE_EVER)
        #imgui.show_demo_window()

    def step(self):
        if not self._started:
            self.ql.run(count=1)
            self._started = True
        else:
            self.ql.emu_start(self.start_address(), self.exit_point(), 0, 1)
        # Process exit?
        if not getattr(self.ql.os, 'PE_RUN', True):
            self._dt = None
        self.capture_state()

    def control_window_frame(self, dt):
        imgui.set_next_window_position(10, 10, imgui.FIRST_USE_EVER)
        imgui.begin('Control', flags=imgui.WINDOW_ALWAYS_AUTO_RESIZE)

        if imgui.button(' Restart '):
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
        imgui.same_line()

        if imgui.button(' Close '):
            self.close()
        imgui.end()


def run_window(update_fn):
    window = pyglet.window.Window(width=1280, height=720, resizable=True)
    pyglet.gl.glClearColor(0.4, 0.5, 0.6, 1)
    imgui.create_context()
    io = imgui.get_io()
    io.ini_file_name = b''      # Disable imgui.ini
    #io.config_windows_move_from_title_bar_only = True

    imgui.style_colors_dark()   # Set dark style
    style = imgui.get_style()
    style.frame_rounding = 3.0
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

class DumOut:
    def write(self, text):
        pass


if __name__ == "__main__":
    #import sys
    #sys.stdout = DumOut()
    emu = QilingView()
    run_window(emu.frame)
