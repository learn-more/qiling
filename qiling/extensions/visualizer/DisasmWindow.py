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
    if name == '[PE]':
        name = ql.targetname

    # We were unable to find a 'pretty' label, so just represent it as module + offset
    if name == '-':
        return '%0*x' % (ql.archbit // 4, address)
    else:
        return '%s + 0x%03x' % (name, offset)


def calc_text_content_size(text):
    text_size = imgui.calc_text_size(text)
    style = imgui.get_style()
    return text_size.x + style.item_spacing.x * 2


class DisasmWindow:
    def __init__(self):
        self.lines = []
        self.md = None
        self._widths = []
        self._history = []

    def reset(self):
        self.lines = []
        self.md = None
        self._widths = []
        self._history = []

    def capture(self, ql, address):
        if not self.md:
            self.md = ql.create_disassembler()
            self.md.detail = True   # Ask capstone to add instruction details
            self.md.skipdata = True

        self.lines = []
        if address:
            # Gather a few instructions before the current instruction
            if self._history and abs(address - self._history[0]) < 20:
                data = ql.mem.read(self._history[0], address - self._history[0])
                decoded = list(self.md.disasm(data, self._history[0]))
            else:
                self._history = []
                decoded = []

            data = ql.mem.read(address, 200)
            decoded.extend(self.md.disasm(data, address))
            bits = ql.archbit // 4
            for insn in decoded:
                addr_name = addr_to_str(ql, insn.address)

                addr = '%0*x' % (bits, insn.address)
                selected = address == insn.address

                # Ensure there are max 2 lines visible before the active line
                if selected:
                    self._history.append(address)
                    self._history = self._history[-2:]

                data = ''
                for byte in insn.bytes:
                    data += ('%02x ' % byte)

                op_str = insn.op_str
                if insn.id != capstone.CS_OP_INVALID and len(insn.operands) == 1:
                    op = insn.operands[0]
                    if op.type == capstone.CS_OP_IMM:
                        op_str = addr_to_str(ql, op.imm)
                    elif op.type == capstone.CS_OP_MEM:
                        mem = op.mem
                        if mem.base == 0 and mem.segment == 0 and mem.scale == 1:
                            assert op.size == 4, op.size
                            ptr_name = addr_to_str(ql, mem.disp)
                            dest = ql.mem.read_ptr(mem.disp)
                            dest_name = addr_to_str(ql, dest)
                            op_str = 'dword ptr [%s]; %s' % (ptr_name, dest_name)

                insn_text = f'{insn.mnemonic} {op_str}'
                self.lines.append((addr, addr_name, selected, data, insn_text))

            # Since we do not have an active imgui context here, we just store the longest string,
            # so that we can calculate the text width later
            self._widths = ['', '', '']
            for addr, addr_name, _, data, _ in self.lines:
                for idx, value in enumerate([addr, addr_name, data]):
                    if len(value) > len(self._widths[idx]):
                        self._widths[idx] = value

    def frame(self):
        imgui.set_next_window_position(240, 100, imgui.FIRST_USE_EVER)
        imgui.set_next_window_size(900, 300, imgui.FIRST_USE_EVER)
        imgui.begin('Disasm')
        imgui.columns(4)
        imgui.separator()
        if self._widths:
            # We need an active imgui context to calculate text width,
            # so we delegated width calculation until we have one
            if isinstance(self._widths[0], str):
                for idx, text in enumerate(self._widths):
                    self._widths[idx] = calc_text_content_size(text)
                print(self._widths)

        for idx, name in enumerate(['Address', 'Module Address', 'Bytes', 'Instruction']):
            imgui.text(name)
            if idx < len(self._widths):
                imgui.set_column_width(-1, self._widths[idx])
            imgui.next_column()
        if self._widths:
            self._widths = []
        imgui.separator()

        for addr, addr_name, selected, data, insn_text in self.lines:
            imgui.selectable(addr, selected, flags=imgui.SELECTABLE_SPAN_ALL_COLUMNS)
            #imgui.selectable(addr, selected)
            imgui.next_column()

            imgui.text(addr_name)
            imgui.next_column()

            imgui.text(data)
            imgui.next_column()

            imgui.text(insn_text)
            imgui.next_column()

        imgui.columns(1)
        imgui.end()
