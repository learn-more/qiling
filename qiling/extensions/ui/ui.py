try:
    import imgui, pyglet, sys
except ImportError as ex:
    print('---')
    print('Please install imgui with pyglet support:')
    print('`pip install imgui[pyglet]`')
    print('---')
    raise
from imgui.integrations.pyglet import create_renderer
from qiling import Qiling

from qiling.extensions.ui.windows import DisasmWindow
from qiling.extensions.ui.windows import LogWindow
from qiling.extensions.ui.windows import RegistersWindow
from qiling.extensions.ui.windows import SelectExampleWindow


SPEED_TEXT = ['0 ms', '50 ms', '100 ms', '300 ms', '1 s']
SPEED_VALUES = [0,     0.05,    0.1,     0.3,      1.0]


class LayoutHelper:
    def __init__(self):
        self.margin = None
        self.window_padding = None
        self.top_frame_bottom = None

    def top_frame(self):
        """ Centered, docked to the top of the screen
        """
        if not self.margin:
            self.margin = imgui.get_style().frame_padding
            self.window_padding = imgui.get_style().window_padding
        imgui.set_next_window_position(imgui.get_io().display_size.x * 0.5, self.margin.y, imgui.FIRST_USE_EVER, 0.5)

    def left_frame(self):
        """Docked to the top left of the screen
        """
        if not self.top_frame_bottom:
            self.top_frame_bottom = imgui.get_cursor_screen_pos().y + self.window_padding.y
        imgui.set_next_window_position(self.margin.x, self.margin.y, imgui.FIRST_USE_EVER)

    def bottom_frame(self):
        """Docked to the bottom of the screen
        """
        bottom = imgui.get_io().display_size.y
        imgui.set_next_window_position(self.margin.x, bottom - self.margin.y, imgui.FIRST_USE_EVER, 0, 1.)
        imgui.set_next_window_size(1000, 210, imgui.FIRST_USE_EVER)

    def center_frame(self):
        #if not self._wait:
        imgui.set_next_window_position(240, 100, imgui.FIRST_USE_EVER)
        imgui.set_next_window_size(900, 300, imgui.FIRST_USE_EVER)

class QilingUi:
    def __init__(self, *args, **kwargs):
        self._cursor = -2
        self.log = LogWindow()
        self.registers = RegistersWindow()
        self.disasm = DisasmWindow()
        self.select_example = SelectExampleWindow()
        self.layout = LayoutHelper()
        self.ql = None
        self._started = False
        self._speed = 3     # 300 ms
        self._dt = None
        self._args = args
        self._kwargs = kwargs
        # If we have arguments passed in, assume we are used as Qiling drop-in replacement!
        if self._args or self._kwargs:
            self.init()

    def run(self):
        window = pyglet.window.Window(width=1280, height=720, resizable=True)
        pyglet.gl.glClearColor(0.4, 0.5, 0.6, 1)
        imgui.create_context()
        io = imgui.get_io()
        io.ini_file_name = b''      # Disable imgui.ini
        #io.config_windows_move_from_title_bar_only = True
        imgui.style_colors_dark()   # Set dark style
        style = imgui.get_style()
        style.frame_rounding = 3.0
        style.scrollbar_rounding = 3.0
        style.window_rounding = 0.
        style.window_border_size = 0.
        impl = create_renderer(window)

        def draw(dt):
            imgui.new_frame()
            self.frame(window, dt)
            window.clear()
            imgui.render()
            impl.render(imgui.get_draw_data())

        pyglet.clock.schedule_interval(draw, 1/120.)
        pyglet.app.run()
        impl.shutdown()


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
        self.ql = Qiling(*self._args, **self._kwargs,
                    log_override=self.log.create_logger())
        # Now process stuff logged during creation:
        self.log.set_ql(self.ql)
        self.capture_state()
        self.layout = LayoutHelper()

    def capture_state(self):
        addr = self.start_address()
        self.disasm.capture(self.ql, addr)
        self.registers.capture(self.ql, addr)

    def frame(self, window, dt):
        imgui.set_next_window_collapsed(True, imgui.FIRST_USE_EVER)
        imgui.show_demo_window()

        if self.ql:
            self.frame_ql(window, dt)
        else:
            self.frame_choose()

    def frame_choose(self):
        # No Qiling instance is created, so let the user choose a binary!
        res = self.select_example.frame()
        if res:
            # We got a binary, initialize it!
            self._args, self._kwargs = res
            self.init()

    def frame_ql(self, window, dt):
        self.handle_auto_step(dt)

        self.layout.top_frame()
        if not self.control_window_frame(dt):
            return

        self.layout.left_frame()
        self.registers.frame()

        self.layout.bottom_frame()
        self.log.frame()

        self.layout.center_frame()
        self.disasm.frame()

    def handle_auto_step(self, dt):
        if self._dt is not None:
            self._dt += dt
            if self._dt >= SPEED_VALUES[self._speed]:
                self._dt = 0.0
                self.step()

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
        """Draw the control window

        Args:
            dt (float): Time since last call
        """
        imgui.begin('Control', flags=imgui.WINDOW_ALWAYS_AUTO_RESIZE)

        if imgui.button(' Restart '):
            self.init()
            imgui.end()
            return False
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

        path = self.ql.path # If the user closes the dialog, we cannot use ql anymore
        rootfs = self.ql.rootfs

        if imgui.button(' Close '):
            self.close()

        imgui.separator()
        imgui.text(f'binary: {path}')
        imgui.text(f'rootfs: {rootfs}')
        imgui.end()
        return True


if __name__ == "__main__":
    ui = QilingUi()
    ui.run()

