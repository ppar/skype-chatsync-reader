"""
Yet another ad hoc variable dumper a la PHP's var_dump()

Copyright 2017, Peter Parkkali
MIT License.
"""

def dump_var(var, level = 0, _var_index = None):

    PAD = "  "
    MAX_WIDTH = 180

    # Prepend index
    index_str = "[?] "
    if level == 0:
        index_str = ""
    if _var_index != None:
        index_str = "[{}] ".format(_var_index)

    # Printable types - end of recursion - int
    if type(var) in [int]:
        varstring = (level * PAD) + index_str + "<" + type(var).__name__ + "> " + repr(var)

        # Truncate to max width
        if len(varstring) > MAX_WIDTH:
            varstring = varstring[:MAX_WIDTH-3] + "..."

        print(varstring)
        return

    # Printable types - end of recursion - str
    if type(var) in [str]:
        varstring = (level * PAD) + index_str + "<" + type(var).__name__ + "(" + str(len(var)) + ")> " + repr(var)

        # Truncate to max width
        if len(varstring) > MAX_WIDTH:
            varstring = varstring[:MAX_WIDTH-3] + "..."

        print(varstring)
        return

    # Recurse - sequences - lists
    if type(var) in [list]:
        print((level * PAD) + index_str + "<" + type(var).__name__ + "> ")
        try:
            for i, v in enumerate(var):
                dump_var(v, level = level + 1, _var_index = i)
            return
        except AttributeError:
            for v in var:
                dump_var(v, level = level + 1)
            return

    # Special case for SkypeChatSyncScanner's "Field" tuples
    if isinstance(var, tuple) and type(var).__name__ == "Field":
        lst = []
        for i, v in var._asdict().iteritems():
            lst.append("[{}]: {}".format(i, repr(v)))

        varstring = (level * PAD) + index_str + "<Tuple:" + type(var).__name__ + ">" + ", ".join(lst)
        if len(varstring) > MAX_WIDTH:
            varstring = varstring[:MAX_WIDTH-3] + "..."
        print(varstring)
        return

    # Recurse - sequences - tuples
    if isinstance(var, tuple):
        #print(repr(var))
        print((level * PAD) + index_str + "<Tuple:" + type(var).__name__ + ">")

        try:
            # Might only work for namedtuples
            # -- gets names of props instead of indexes
            for i, v in var._asdict().iteritems():
                dump_var(v, level = level + 1, _var_index = i)

        except AttributeError:
            # For regular tuples
            # -- gets indexes of props
            for i, v in enumerate(var):
                dump_var(v, level = level + 1, _var_index = i)

        return

    # Recurse - dicts
    if type(var) in [dict]:
        print((level * PAD) + index_str + "<Dict:" + type(var).__name__ + ">")
        for i, v in var.iteritems():
            dump_var(v, level = level + 1, _var_index = i)
        return

    # Recurse - objects
    if isinstance(var, object):
        print((level * PAD) + index_str + "<Object:" + type(var).__name__ + ">")
        try:
            for i, v in var.__dict__.iteritems():
                dump_var(v, level = level + 1, _var_index = i)
        except AttributeError:
            # FIXME
            dump_var(repr(var), level = level + 1)
        return

    # ???
    print((level * PAD) + prefix + "<" + type(var).__name__ + ">" + "UNKNOWN TYPE " + repr(type(var)))
