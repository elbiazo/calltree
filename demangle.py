from binaryninja import demangle_ms, demangle_gnu3


def demangle_name(bv, function_name):
    ms = demangle_ms(bv.arch, function_name)
    gnu = demangle_gnu3(bv.arch, function_name)

    if ms[0] != None:
        return "::".join(ms[1])
    elif gnu[0] != None:
        return "::".join(gnu[1])
    else:
        return function_name
