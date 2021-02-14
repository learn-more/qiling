

def format_module_name(ql, name):
    # Replace the [PE] placeholder with the actual name
    if name == '[PE]' or name == '[module]':
        name = ql.targetname

    # Shorten the path if possible
    if ql.rootfs in name:
        name = name.replace(ql.rootfs, '{rootfs}')
    return name


def addr_to_str(ql, address):
    """Try to convert an address to a human-readable string

    Args:
        ql (Qiling): The current Qiling instance
        address (int): The address

    Returns:
        string: The pretty-printed result
    """
    offset, name = ql.os.get_offset_and_name(address)

    hooks = ql.get_hook_address(address)
    if hooks:
        for hook in hooks:
            # Extract api hooks (f.e. uefi)
            name = getattr(hook.callback, '__name__', None)
            closure = getattr(hook.callback, '__closure__', None)
            if name == 'wrapper' and closure:
                fnc = closure[0].cell_contents
                name = getattr(fnc, '__name__', None)
                if name:
                    return name

    pe = ql.loader
    if hasattr(pe, 'import_symbols'):
        # Search for it in ql.loader.import_symbols[address]['name']:
        sym = pe.import_symbols.get(address, None)
        if sym:
            return '%s.%s' % (sym['dll'], sym['name'].decode())

    # We were unable to find a 'pretty' label, so just represent it as module + offset
    if name == '-':
        return '%0*x' % (ql.archbit // 4, address)
    else:
        name = format_module_name(ql, name)
        return '%s + 0x%03x' % (name, offset)
