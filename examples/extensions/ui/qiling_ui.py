from pathlib import Path
from qiling import Qiling
from qiling.extensions.ui import QilingUi

# Remove 'extensions/ui/qiling_ui.py' from the path
EXAMPLES_PATH = Path(__file__).parent.parent.parent
ROOTFS_DIR = EXAMPLES_PATH / 'rootfs' / 'x86_windows'

def qiling_ui_example(run_ql=False):
    """Show that QilingUi can be used as drop-in replacement for Qiling in simple cases

    Args:
        run_ql (bool, optional): Run Qiling instead of QilingUi. Defaults to False.
    """
    argv = [str(ROOTFS_DIR / 'bin' / 'x86_hello.exe')]
    rootfs = str(ROOTFS_DIR)
    if run_ql:
        ql = Qiling(argv, rootfs, output="debug")
    else:
        ql = QilingUi(argv, rootfs, output="debug")
    ql.run()


if __name__ == "__main__":
    qiling_ui_example()
