import imgui
from pathlib import Path

SELF_PATH = Path(__file__).parent
SRC_PATH = SELF_PATH.parent.parent.parent
ROOTFS_BASE_PATH = SRC_PATH / 'examples' / 'rootfs'
#ROOTFS_PATH_32 = SRC_PATH / 'examples' / 'rootfs' / 'x86_windows'
#ROOTFS_PATH_64 = SRC_PATH / 'examples' / 'rootfs' / 'x8664_windows'

#[ROOTFS_PATH_64 / 'bin' /  'cmdln64.exe'],
#                    ROOTFS_PATH_64,
#                    'debug'


class SelectBinaryWindow:
    def __init__(self):
        self._rootfs_items = ['x86_windows', 'x8664_windows']
        self._rootfs = 1
        self._binary_items = []
        self._binary = -1
        self._loglevel_items = ['default', 'disasm', 'debug', 'dump']
        self._loglevel = 0
        self.update_binaries()

    def rootfs_dir(self):
        return ROOTFS_BASE_PATH / self._rootfs_items[self._rootfs]

    def loglevel(self):
        return self._loglevel_items[self._loglevel]

    def binary(self):
        return self._binary_items[self._binary]

    def update_binaries(self):
        self._binary_items = []
        self._binary = 0
        for example in (self.rootfs_dir() / 'bin').iterdir():
            if example.suffix != '.zip':
                self._binary_items.append(example.name)


    def frame(self):
        imgui.begin('Get started', flags=imgui.WINDOW_ALWAYS_AUTO_RESIZE)
        imgui.text_unformatted('Rootfs:')
        changed, self._rootfs = imgui.combo('##Rootfs', self._rootfs, self._rootfs_items)
        if changed:
            self.update_binaries()

        #text_centered('Choose a binary')
        imgui.text_unformatted('Binary:')
        _, self._binary = imgui.combo('##Binary', self._binary, self._binary_items)
        imgui.spacing()
        imgui.separator()
        imgui.text_unformatted('Loglevel:')
        _, self._loglevel = imgui.combo('##Loglevel', self._loglevel, self._loglevel_items)

        imgui.spacing()

        if imgui.button(' Run '):
            argv = [self.rootfs_dir() / 'bin' / self.binary()]
            imgui.end()
            return argv, self.rootfs_dir(), self.loglevel()

        imgui.end()
        #return argv, rootfs, output
        return False

