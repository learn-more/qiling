import capstone, imgui

def addr_to_str(ql, address):
    """Try to convert an address to a human-readable string

    Args:
        ql (Qiling): The current Qiling instance
        address (int): The address

    Returns:
        string: The pretty-printed result
    """
    offset, name = ql.os.get_offset_and_name(address)

    pe = ql.loader
    if hasattr(pe, 'import_symbols'):
        # Optimal case, we have an exact match
        sym = pe.import_symbols.get(address, None)
        if sym:
            return '%s.%s' % (sym['dll'], sym['name'].decode())

    # Replace the [PE] placeholder with the actual name
    if name == '[PE]' or name == '[module]':
        name = ql.targetname

    # We were unable to find a 'pretty' label, so just represent it as module + offset
    if name == '-':
        return '%0*x' % (ql.archbit // 4, address)
    else:
        if ql.rootfs in name:
            name = name.replace(ql.rootfs, '{rootfs}')
        return '%s + 0x%03x' % (name, offset)


def calc_text_content_size(text):
    text_size = imgui.calc_text_size(text)
    style = imgui.get_style()
    return text_size.x + style.item_spacing.x * 2

# Zydis::ResolveOpValue
# _dbg_getbranchdestination
# cp.InGroup(CS_GRP_JUMP) || cp.InGroup(CS_GRP_CALL) || cp.IsLoop()
# https://github.com/x64dbg/capstone_wrapper/blob/master/capstone_wrapper.cpp
def pprint_op_str(ql, insn):
    if insn.id != capstone.CS_OP_INVALID and len(insn.operands) == 1:
        op = insn.operands[0]
        if op.type == capstone.CS_OP_IMM:
            return f'<{addr_to_str(ql, op.imm)}>'
        elif op.type == capstone.CS_OP_MEM:
            mem = op.mem
            if mem.base == 0 and mem.segment == 0 and mem.scale == 1:
                assert op.size == 4, op.size
                ptr_name = addr_to_str(ql, mem.disp)
                dest = ql.mem.read_ptr(mem.disp)
                dest_name = addr_to_str(ql, dest)
                return 'dword ptr [%s]; %s' % (ptr_name, dest_name)
            elif mem.base == ql.reg.uc_pc and mem.segment == 0 and mem.scale == 1:
                # 'qword ptr [rip + 0x8ba]'
                assert op.size == 8
                ptr = insn.address + mem.disp + insn.size
                ptr_name = addr_to_str(ql, ptr)
                dest = ql.mem.read_ptr(ptr)
                dest_name = addr_to_str(ql, dest)
                return 'qword ptr [%s]; %s' % (ptr_name, dest_name)
    return insn.op_str


class Insn:
    def __init__(self, insn, ql):
        self.addr = insn.address
        self.addr_str = '%0*x' % (ql.archbit // 4, insn.address)
        self.addr_name = addr_to_str(ql, insn.address)
        self.data = ' '.join(f'{byte:02x}' for byte in insn.bytes)
        self.mnem = insn.mnemonic
        if insn.id != capstone.CS_OP_INVALID:
            self.is_call = capstone.CS_GRP_CALL in insn.groups
            self.is_ret = capstone.CS_GRP_RET in insn.groups
            self.is_jmp = capstone.CS_GRP_JUMP in insn.groups
            if capstone.CS_GRP_INT in insn.groups:
                self.op_str = insn.op_str
            else:
                self.op_str = pprint_op_str(ql, insn)
        else:
            self.is_call = self.is_ret = self.is_jmp = False
            self.op_str = insn.op_str

    def add_mnem(self):
        if self.is_call or self.is_ret:
            imgui.push_style_color(imgui.COLOR_BUTTON, 0., 0.6, 0.5)
            imgui.button(self.mnem)
            imgui.pop_style_color()
        elif self.is_jmp:
            imgui.push_style_color(imgui.COLOR_BUTTON, 0.6, 0.5, 0)
            imgui.button(self.mnem)
            imgui.pop_style_color()
        else:
            imgui.text(self.mnem)
        imgui.same_line()
        imgui.selectable(self.op_str)


class History:
    def __init__(self):
        self._stack = []

    def push(self, address):
        # Still at the same address?
        if self._stack and self._stack[-1] == address:
            return
        self._stack.append(address)

    def get(self, address, max_diff=20):
        # Still at the same address?
        if len(self._stack) > 1 and self._stack[-1] == address:
            return self._stack[0]
        self._stack = self._stack[-2:]
        if self._stack and 0 < (address - self._stack[0]) < max_diff:
            return self._stack[0]
        self._stack = []
        return None


class DisasmWindow:
    def __init__(self):
        self.lines = []
        self.md = None
        self._widths = []
        self._history = History()

    def reset(self):
        self.lines = []
        self.md = None
        self._widths = []
        self._history = History()

    def capture(self, ql, address):
        if not self.md:
            self.md = ql.create_disassembler()
            self.md.detail = True   # Ask capstone to add instruction details
            self.md.skipdata = True

        self.lines = []
        if address:
            # Gather a few instructions before the current instruction
            history = self._history.get(address)
            if history:
                data = ql.mem.read(history, address - history)
                decoded = list(self.md.disasm(data, history))
            else:
                #self._history = []
                decoded = []

            data = ql.mem.read(address, 200)
            decoded.extend(self.md.disasm(data, address))
            bits = ql.archbit // 4
            for insn in decoded:
                insn = Insn(insn, ql)
                selected = address == insn.addr

                if selected:
                    self._history.push(address)

                self.lines.append((insn, selected))

            # Since we do not have an active imgui context here, we just store the longest string,
            # so that we can calculate the text width later
            self._widths = ['', '', '']
            for cols in [(insn.addr_str, insn.addr_name, insn.data) for insn, _ in self.lines]:
                for idx, value in enumerate(cols):
                    if len(value) > len(self._widths[idx]):
                        self._widths[idx] = value

    def frame(self, flags):
        imgui.begin('Disasm', flags=flags)
        imgui.columns(4)
        imgui.separator()
        if self._widths:
            # We need an active imgui context to calculate text width,
            # so we delegated width calculation until we have one
            if isinstance(self._widths[0], str):
                for idx, text in enumerate(self._widths):
                    self._widths[idx] = calc_text_content_size(text)

        for idx, name in enumerate(['Address', 'Module Address', 'Bytes', 'Instruction']):
            imgui.text(name)
            if idx < len(self._widths):
                imgui.set_column_width(-1, self._widths[idx])
            imgui.next_column()
        #if self._widths:
        #    self._widths = []
        imgui.separator()

        # Change the style for our instruction buttons
        imgui.push_style_var(imgui.STYLE_FRAME_PADDING, imgui.Vec2(2, 0))
        imgui.push_style_var(imgui.STYLE_FRAME_ROUNDING, 2.)

        for insn, selected in self.lines:
            imgui.selectable(insn.addr_str, selected, flags=imgui.SELECTABLE_SPAN_ALL_COLUMNS)
            imgui.next_column()

            imgui.text(insn.addr_name)
            imgui.next_column()

            imgui.text(insn.data)
            imgui.next_column()

            insn.add_mnem()
            imgui.next_column()

        imgui.pop_style_var(2)

        imgui.columns(1)
        imgui.end()
