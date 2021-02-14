import imgui
from pathlib import Path

SELF_PATH = Path(__file__).parent
SRC_PATH = SELF_PATH.parent.parent.parent.parent
ROOTFS_BASE_PATH = SRC_PATH / 'examples' / 'rootfs'


class SelectExampleWindow:
    def __init__(self):
        #self._rootfs_items = ['x86_windows', 'x8664_windows']
        self._rootfs_items = []
        self._rootfs = 0
        self._binary_items = []
        self._binary = -1
        self._loglevel_items = ['default', 'disasm', 'debug', 'dump']
        self._loglevel = 0
        self._update_rootfs()
        self._update_binaries()

    def rootfs_dir(self):
        return ROOTFS_BASE_PATH / self._rootfs_items[self._rootfs]

    def loglevel(self):
        return self._loglevel_items[self._loglevel]

    def binary(self):
        return self._binary_items[self._binary]

    def _update_rootfs(self):
        self._rootfs_items = []
        self._rootfs = 0
        try:
            for rootfs in ROOTFS_BASE_PATH.iterdir():
                if rootfs.is_dir() and (rootfs / 'bin').exists():
                    # Only x86(64) supported for now
                    if not rootfs.name.startswith('x86'):
                        continue
                    # Don't have access to this to test it
                    if 'macos' in rootfs.name or 'freebsd' in rootfs.name:
                        continue
                    self._rootfs_items.append(rootfs.name)
        except FileNotFoundError as ex:
            self._rootfs_items = []

    def _update_binaries(self):
        self._binary_items = []
        self._binary = 0
        if self._rootfs_items:
            try:
                for example in (self.rootfs_dir() / 'bin').iterdir():
                    if example.suffix != '.zip':
                        self._binary_items.append(example.name)
            except FileNotFoundError as ex:
                self._binary_items = []

    def show_help(self):
        imgui.begin('QilingUi - No rootfs found', flags=imgui.WINDOW_ALWAYS_AUTO_RESIZE)
        imgui.text('QilingUi was unable to find any file to execute.')
        imgui.text('Are you trying to run this script from a PyPI installation?')
        imgui.text('Please use QilingUi as drop-in for Qiling:')
        imgui.text('')
        imgui.text('ql = Qiling(["rootfs/x86_windows/bin/x86_hello.exe"], "rootfs/x86_windows")')
        imgui.text('ql.run()')
        imgui.text('')
        imgui.text('Alternatively, clone the qiling repository and run this script directly')
        imgui.end()

    def frame(self):
        if not self._rootfs_items or not self._binary_items:
            self.show_help()
            return

        imgui.begin('Get started', flags=imgui.WINDOW_ALWAYS_AUTO_RESIZE)
        imgui.text_unformatted('Rootfs:')
        changed, self._rootfs = imgui.combo('##Rootfs', self._rootfs, self._rootfs_items, 200)
        if changed:
            self._update_binaries()

        imgui.text_unformatted('Binary:')
        _, self._binary = imgui.combo('##Binary', self._binary, self._binary_items, 200)
        imgui.spacing()
        imgui.separator()
        imgui.text_unformatted('Loglevel:')
        _, self._loglevel = imgui.combo('##Loglevel', self._loglevel, self._loglevel_items)

        imgui.spacing()

        result = False
        if imgui.button(' Run '):
            # A binary was selected, let's return this info!
            argv = [str(self.rootfs_dir() / 'bin' / self.binary())]
            rootfs = str(self.rootfs_dir())
            args = [argv, rootfs]
            kwargs = {'output': self.loglevel()}
            result = args, kwargs

        imgui.end()
        return result

