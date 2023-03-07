from binaryninja import demangle_ms, demangle_gnu3, get_qualified_name


def demangle_name(bv, function_name):
    ms = demangle_ms(bv.arch, function_name)
    gnu = demangle_gnu3(bv.arch, function_name)

    if ms[0] != None:
        return get_qualified_name(ms[1])
    elif gnu[0] != None:
        return get_qualified_name(gnu[1])
    else:
        return function_name
