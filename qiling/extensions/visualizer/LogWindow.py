import imgui, logging
from qiling.utils import QilingColoredFormatter, FMT_STR


LOGGER_NUMBER = 123

class LogWindow(logging.Handler):
    def __init__(self):
        super().__init__()
        self._msgs = []
        self._unformatted = []
        self._scroll_to_bottom = 0
        self.level = logging.DEBUG

    def emit(self, record):
        if self.formatter:
            msg = self.format(record)
            msg = msg.replace('\033[9', '\033[3')   # pyimgui does not support the 'BRIGHT' colors
            self._msgs.append(msg)
            self._scroll_to_bottom = 2
        else:
            # We are not able to format records yet (no ql object),
            # so store them for later
            self._unformatted.append(record)

    def create_logger(self):
        global LOGGER_NUMBER
        log = logging.getLogger(f'ql_ui{LOGGER_NUMBER}')
        LOGGER_NUMBER += 1
        log.propagate = False
        log.addHandler(self)
        return log

    def set_ql(self, ql):
        assert not self.formatter
        formatter = QilingColoredFormatter(ql, FMT_STR)
        self.setFormatter(formatter)

        # Now that we have a formatter, process records we could not process before
        unformatted = self._unformatted
        self._unformatted = False   # Ensure we cannot use this anymore
        for record in unformatted:
            self.emit(record)

    def clear(self):
        self._msgs = []
        self._unformatted = []
        self.formatter = None

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
