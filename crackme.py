import argparse
import struct
import binascii
import sys

from opcodes import OPCODES

SUPPORTED_DSO_VERSIONS = (50,)
U32_BYTES = 4
FLOAT_BYTES = 8


class DSO:
    version = SUPPORTED_DSO_VERSIONS[0]
    global_strings = []
    function_strings = []
    global_floats = []
    function_floats = []
    code = []
    line_break_count = 0
    string_references = []

    @staticmethod
    def from_stream(stream):
        dso = DSO()

        dso.protocol_version = parse_protocol_version(stream)
        dso.global_strings = parse_string_table(stream)
        dso.global_strings[47] = dso.global_strings[46][1:]  # lol
        dso.function_strings = parse_string_table(stream)
        dso.global_floats = parse_float_table(stream)
        dso.function_floats = parse_float_table(stream)
        dso.var_to_reg_map = parse_local_var_to_reg_map(stream)
        dso.code, dso.line_break_count = parse_code(stream)
        dso.string_references = parse_string_references(stream)

        for offset, ips in dso.string_references:
            for ip in ips:
                dso.code[ip] = offset

        prev_field = None
        prev_object = None
        cur_object = None
        current_register = -1
        current_variable = None
        global_vars = {}
        stack_depth = 1
        callframe_stack = [{}]
        stack = [0] * 1024
        registers = [0] * 8
        sp = 0
        call_stack = []

        functions = [
            ("__main", "$input", "$input", 1, 8, 1, 12),
            ("__putc", "$input", "$input", 1, 1, 76442, 76453),
            ("__getc", "$input", "$input", 1, 1, 76514, 76525),
        ]
        i = 12
        while i < len(dso.code):
            instruction = dso.code[i]
            i += 1
            print(sp, stack[max(sp - 8, 0) : sp + 8])
            print(registers)
            if is_opcode(instruction):
                op = OPCODES[u8(instruction)]
                print(i - 1, op)
                if op == "OP_FUNC_DECL":
                    fn_name = dso.global_strings[dso.code[i]].decode()
                    fn_namespace = dso.global_strings[
                        int.from_bytes(dso.code[i + 2], "little")
                    ].decode()
                    fn_package = dso.global_strings[
                        int.from_bytes(dso.code[i + 4], "little")
                    ].decode()
                    has_body = dso.code[i + 6][0] & 1 != 0
                    argc = dso.code[i + 8][0]
                    regc = dso.code[i + 9][0]
                    definition_ip = i if has_body else 0
                    start_ip = definition_ip + argc + 10
                    functions.append(
                        (
                            fn_name,
                            fn_namespace,
                            fn_package,
                            argc,
                            regc,
                            definition_ip,
                            start_ip,
                        )
                    )
                    print(functions[-1])
                    i = int.from_bytes(dso.code[i + 7], "little")
                    continue
                elif op == "OP_SETCURVAR_CREATE":
                    var = dso.global_strings[dso.code[i]]
                    if isinstance(var, bytes):
                        var = var.decode()
                    print(var)
                    i += 2
                    prev_field = None
                    prev_object = None
                    cur_object = None
                    current_register = -1
                    if var[0] == "$":
                        if var in global_vars:
                            current_variable = [var]
                            continue
                        global_vars[var] = None
                        current_variable = [var]
                    elif stack_depth > 0:
                        if var in callframe_stack[stack_depth - 1]:
                            current_variable = [
                                stack_depth - 1,
                                var,
                                callframe_stack[stack_depth - 1][var],
                            ]
                            continue
                        callframe_stack[stack_depth - 1][var] = None
                        current_variable = [
                            stack_depth - 1,
                            var,
                            callframe_stack[stack_depth - 1][var],
                        ]
                    else:
                        current_variable = None
                        print("accessing local var in global scope failed: " + var)
                elif op == "OP_SETCURVAR_ARRAY_CREATE":
                    var = stack[sp]
                    if isinstance(var, bytes):
                        var = var.decode()
                    print(var)
                    prev_field = None
                    prev_object = None
                    cur_object = None
                    current_register = -1
                    if var[0] == "$":
                        if var in global_vars:
                            current_variable = [var]
                            continue
                        global_vars[var] = None
                        current_variable = [var]
                    elif stack_depth > 0:
                        if var in callframe_stack[stack_depth - 1]:
                            current_variable = [
                                stack_depth - 1,
                                var,
                                callframe_stack[stack_depth - 1][var],
                            ]
                            continue
                        callframe_stack[stack_depth - 1][var] = None
                        current_variable = [
                            stack_depth - 1,
                            var,
                            callframe_stack[stack_depth - 1][var],
                        ]
                    else:
                        current_variable = None
                        print(
                            "accessing local var in global scope failed: "
                            + var.decode()
                        )
                elif op == "OP_CALLFUNC":
                    global_vars[
                        "$input"
                    ] = "flag{vmprotect?_where_we_re_going_we_ll_need_protecti0n_FR0Mm_th3_vms}"  # it gets overwritten at beginning of main
                    fn_name = dso.global_strings[dso.code[i]].decode()
                    fn_namespace = dso.global_strings[
                        int.from_bytes(dso.code[i + 2], "little")
                    ].decode()
                    call_type = int.from_bytes(dso.code[i + 4], "little")
                    print(fn_name, fn_namespace, call_type)
                    print(global_vars)
                    callframe_stack[stack_depth - 1]["ip"] = i + 5
                    i += 5
                    print(call_stack)
                    if fn_name in [x[0] for x in functions]:
                        fn = [x for x in functions if fn_name == x[0]][0]
                        callframe_stack.append({})
                        stack_depth += 1
                        for j in range(fn[3]):
                            reg = int.from_bytes(dso.code[fn[-2] + 10 + j], "little")
                            registers[reg] = call_stack.pop()
                        i = fn[-1]
                    else:
                        if fn_name == "strlen":
                            s = call_stack.pop()
                            call_stack.pop()
                            stack[sp + 1] = len(s)
                            sp += 1
                        elif fn_name == "getSubStr":
                            c = call_stack.pop()
                            b = call_stack.pop()
                            s = call_stack.pop()
                            call_stack.pop()
                            stack[sp + 1] = s[b : b + c]
                            print(stack[sp + 1])
                            sp += 1
                        elif fn_name == "strpos":
                            d = call_stack.pop()
                            s = call_stack.pop()
                            stack[sp + 1] = s.index(bytes(d, "utf-8"))
                            print(stack[sp + 1])
                            sp += 1
                        elif fn_name == "echo":
                            s = call_stack.pop()
                            print(s)
                            sp += 1
                elif op == "OP_RETURN_VOID":
                    if len(callframe_stack) > 0:
                        callframe_stack.pop()
                    if len(call_stack) > 0:
                        call_stack.pop()
                    stack_depth -= 1
                    if len(callframe_stack) > 0:
                        i = callframe_stack[-1]["ip"]
                    sp += 1
                elif op == "OP_RETURN_UINT":
                    if len(callframe_stack) > 0:
                        callframe_stack.pop()
                    if len(call_stack) > 0:
                        call_stack.pop()
                    stack_depth -= 1
                    if len(callframe_stack) > 0:
                        i = callframe_stack[-1]["ip"]
                    stack[sp] = stack[sp]
                elif op == "OP_PUSH_FRAME":
                    print(dso.code[i])
                    call_stack.append(dso.code[sp])
                    i += 1
                elif op == "OP_PUSH":
                    print(stack[sp])
                    call_stack.append(stack[sp])
                    sp -= 1
                elif op == "OP_COMPARE_STR":
                    stack[sp - 1] = 1 if stack[sp] == stack[sp - 1] else 0
                    sp -= 1
                elif op == "OP_LOAD_LOCAL_VAR_STR":
                    reg = int.from_bytes(dso.code[i], "little")
                    current_register = reg
                    prev_field = None
                    prev_object = None
                    cur_object = None
                    val = registers[reg]
                    if not isinstance(val, bytes):
                        val = str(val)
                    stack[sp + 1] = val
                    print(reg, val)
                    sp += 1
                    i += 1
                elif op == "OP_LOAD_LOCAL_VAR_UINT":
                    reg = int.from_bytes(dso.code[i], "little")
                    current_register = reg
                    prev_field = None
                    prev_object = None
                    cur_object = None
                    val = registers[reg]
                    if isinstance(val, bytes):
                        val = int.from_bytes(val, "little")
                    stack[sp + 1] = val
                    print(reg, val)
                    sp += 1
                    i += 1
                elif op == "OP_SAVE_LOCAL_VAR_UINT":
                    reg = int.from_bytes(dso.code[i], "little")
                    current_register = reg
                    prev_field = None
                    prev_object = None
                    cur_object = None
                    print(reg, stack[sp])
                    registers[reg] = stack[sp]
                    i += 1
                elif op == "OP_LOADIMMED_IDENT":
                    val = dso.global_strings[dso.code[i]]
                    if val == b"\x00":
                        val = ""
                    if isinstance(val, bytes) and all(c < 128 for c in val):
                        val = val.decode()
                    print(val)
                    stack[sp + 1] = val
                    sp += 1
                    i += 2
                elif op == "OP_LOADIMMED_UINT":
                    val = int.from_bytes(dso.code[i], "little")
                    print(val)
                    stack[sp + 1] = val
                    sp += 1
                    i += 1
                elif op == "OP_POP_STK":
                    sp -= 1
                elif op == "OP_LOADVAR_UINT":
                    current_register = -1
                    if len(current_variable) > 1:
                        stack[sp + 1] = current_variable[2]
                    elif len(current_variable) == 1:
                        stack[sp + 1] = global_vars[current_variable[0]]
                    else:
                        print("Error no current variable for OP_LOADVAR_UINT")
                        break
                    print(stack[sp + 1])
                    sp += 1
                elif op == "OP_LOADVAR_STR":
                    current_register = -1
                    if len(current_variable) > 1:
                        stack[sp + 1] = current_variable[2]
                    elif len(current_variable) == 1:
                        stack[sp + 1] = global_vars[current_variable[0]]
                    else:
                        print("Error no current variable for OP_LOADVAR_STR")
                        break
                    print(stack[sp + 1])
                    sp += 1
                elif op == "OP_SAVEVAR_STR":
                    if len(current_variable) > 1:
                        sf = current_variable[0]
                        var = current_variable[1]
                        val = current_variable[2]
                        callframe_stack[sf][var] = stack[sp]
                        current_variable[2] = stack[sp]
                    elif len(current_variable) == 1:
                        global_vars[current_variable[0]] = stack[sp]
                    else:
                        print("Error no current variable for OP_SAVEVAR_STR")
                        break
                elif op == "OP_SAVEVAR_UINT":
                    if len(current_variable) > 1:
                        sf = current_variable[0]
                        var = current_variable[1]
                        val = current_variable[2]
                        callframe_stack[sf][var] = stack[sp]
                        current_variable[2] = stack[sp]
                        print(callframe_stack[sf])
                    elif len(current_variable) == 1:
                        global_vars[current_variable[0]] = stack[sp]
                    else:
                        print("Error no current variable for OP_SAVEVAR_UINT")
                        break
                elif op == "OP_REWIND_STR":
                    s = stack[sp - 1]
                    t = stack[sp]
                    if isinstance(s, int):
                        s = str(s)
                    if isinstance(t, int):
                        t = str(t)
                    if isinstance(s, bytes):
                        s = s.decode()
                    if isinstance(t, bytes):
                        t = t.decode()
                    concat = s + t
                    print(concat)
                    stack[sp - 1] = concat
                    sp -= 1
                elif op == "OP_JMP":
                    new = int.from_bytes(dso.code[i], "little")
                    if i - 1 == 3689 or new == 74063:
                        i = 74070 + stack[sp] * 7
                        sp += 1
                        stack[sp] = stack[sp - 1]
                    else:
                        i = new
                    print(new)
                elif op == "OP_JMPIF":
                    print(int.from_bytes(dso.code[i], "little"))
                    val = stack[sp]
                    sp -= 1
                    if val == 0:
                        i += 1
                        continue
                    i = int.from_bytes(dso.code[i], "little")
                elif op == "OP_JMPIFNOT":
                    print(int.from_bytes(dso.code[i], "little"))
                    val = stack[sp]
                    sp -= 1
                    if val == 1:
                        i += 1
                        continue
                    i = int.from_bytes(dso.code[i], "little")
                elif op == "OP_ADD":
                    a = stack[sp]
                    b = stack[sp - 1]
                    if isinstance(a, bytes):
                        a = struct.unpack("f", a)[0]
                    if isinstance(b, bytes):
                        b = struct.unpack("f", b)[0]
                    print(a, b)
                    stack[sp - 1] = a + b
                    sp -= 1
                elif op == "OP_SUB":
                    a = stack[sp]
                    b = stack[sp - 1]
                    if isinstance(a, bytes):
                        a = struct.unpack("f", a)[0]
                    if isinstance(b, bytes):
                        b = struct.unpack("f", b)[0]
                    print(a, b)
                    stack[sp - 1] = a - b
                    sp -= 1
                elif op == "OP_CMPEQ":
                    a = stack[sp]
                    b = stack[sp - 1]
                    if isinstance(a, bytes):
                        a = struct.unpack("f", a)[0]
                    if isinstance(b, bytes):
                        b = struct.unpack("f", b)[0]
                    print(a, b)
                    stack[sp - 1] = 1 if a == b else 0
                    sp -= 1
                elif op == "OP_CMPNE":
                    a = stack[sp]
                    b = stack[sp - 1]
                    if isinstance(a, bytes):
                        a = struct.unpack("f", a)[0]
                    if isinstance(b, bytes):
                        b = struct.unpack("f", b)[0]
                    print(a, b)
                    stack[sp - 1] = 1 if a != b else 0
                    sp -= 1
                elif op == "OP_CMPGE":
                    a = stack[sp]
                    b = stack[sp - 1]
                    if isinstance(a, bytes):
                        a = struct.unpack("f", a)[0]
                    if isinstance(b, bytes):
                        b = struct.unpack("f", b)[0]
                    print(a, b)
                    stack[sp - 1] = 1 if a >= b else 0
                    sp -= 1
                elif op == "OP_CMPLE":
                    a = stack[sp]
                    b = stack[sp - 1]
                    if isinstance(a, bytes):
                        a = struct.unpack("f", a)[0]
                    if isinstance(b, bytes):
                        b = struct.unpack("f", b)[0]
                    print(a, b)
                    stack[sp - 1] = 1 if a <= b else 0
                    sp -= 1
                elif op == "OP_CMPLT":
                    a = stack[sp]
                    b = stack[sp - 1]
                    if isinstance(a, bytes):
                        a = struct.unpack("f", a)[0]
                    if isinstance(b, bytes):
                        b = struct.unpack("f", b)[0]
                    print(a, b)
                    stack[sp - 1] = 1 if a < b else 0
                    sp -= 1
                elif op == "OP_BITAND":
                    a = stack[sp]
                    b = stack[sp - 1]
                    if isinstance(a, bytes):
                        a = int.from_bytes(a, "little")
                    if isinstance(b, bytes):
                        b = int.from_bytes(b, "little")
                    print(a, b)
                    stack[sp - 1] = a & b
                    sp -= 1
                else:
                    print("unimplemented opcode " + op)
                    break

            else:
                print(i - 1, instruction)

        return dso

    def encode(self):
        buffer = eu32(self.version)
        buffer += encode_string_table(self.global_strings)
        buffer += encode_string_table(self.function_strings)
        buffer += encode_float_table(self.global_floats)
        buffer += encode_float_table(self.function_floats)
        buffer += encode_code(self.code, self.line_break_count)
        buffer += encode_string_references(self.string_references)

        return buffer

    def patch_global_strings(self, patches):
        new_global_strings = self.global_strings.copy()
        new_code = self.code.copy()
        new_string_references = []

        for i, new_value in patches.items():
            new_global_strings[int(i)] = new_value.encode()

        for ip, instruction in enumerate(self.code):
            if is_opcode(instruction):
                op = OPCODES[u8(instruction)]
                if op in (
                    "OP_TAG_TO_STR",
                    "OP_LOADIMMED_STR",
                    "OP_DOCBLOCK_STR",
                    "OP_ASSERT",
                ):
                    offset = bytes_to_int(new_code[ip + 1])
                    new_offset = get_new_string_offset(
                        offset, self.global_strings, new_global_strings
                    )

                    new_code[ip + 1] = eu32(new_offset)

        for offset, occurrences in self.string_references:
            new_offset = get_new_string_offset(
                offset, self.global_strings, new_global_strings
            )
            new_string_references.append((new_offset, occurrences))

        self.global_strings = new_global_strings
        self.code = new_code
        self.string_references = new_string_references


def encode_string_references(string_references):
    buffer = eu32(len(string_references))
    for offset, occurrences in string_references:
        buffer += eu32(offset)
        buffer += eu32(len(occurrences))
        for occurrence in occurrences:
            buffer += eu32(occurrence)

    return buffer


def parse_local_var_to_reg_map(stream):
    var_to_reg_map = stream.read(4)
    return var_to_reg_map


def parse_string_references(stream):
    string_references_count = u32(stream)
    string_references = []
    for _ in range(string_references_count):
        offset = u32(stream)
        occurrences_count = u32(stream)
        occurrences = []
        for _ in range(occurrences_count):
            occurrences.append(u32(stream))
        string_references.append((offset, occurrences))

    return string_references


def parse_code(stream):
    instruction_count = u32(stream)
    line_break_pair_count = u32(stream)
    line_break_count = 2 * line_break_pair_count

    code = []
    for i in range(instruction_count):
        peek = stream.read(1)
        if peek == b"\xff":
            code.append(stream.read(U32_BYTES))
        else:
            code.append(peek)

    for i in range(line_break_count):
        code.append(stream.read(U32_BYTES))

    return code, line_break_count


def parse_float_table(stream):
    floats_count = u32(stream)
    format_string = "<" + "d" * floats_count
    return list(struct.unpack(format_string, stream.read(floats_count * FLOAT_BYTES)))


def encode_float_table(float_table):
    format_string = "<" + "d" * len(float_table)
    return eu32(len(float_table)) + struct.pack(format_string, *float_table)


def is_opcode(instruction):
    return len(instruction) == 1 and u8(instruction) < len(OPCODES)


def get_new_string_offset(offset, string_table, new_string_table):
    string_index = offset_to_string_index(offset, string_table)
    new_offset = string_index_to_offset(string_index, new_string_table)

    return new_offset


def get_raw_string_table(string_table):
    return b"\x00".join(string_table)


def encode_string_table(string_table):
    raw_strings = get_raw_string_table(string_table)
    return eu32(len(raw_strings)) + raw_strings


def encode_code(code, line_break_count):
    buff = b""
    for instruction in code[0 : len(code) - line_break_count]:
        if len(instruction) == 4:
            buff += b"\xff"

        buff += instruction

    for instruction in code[len(code) - line_break_count :]:
        buff += instruction

    return eu32(len(code) - line_break_count) + eu32(line_break_count // 2) + buff


def eu32(v):
    try:
        return struct.pack("<I", v)
    except Exception as e:
        raise ValueError(f"can't encode {v} as u32") from e


def bytes_to_int(one_or_four_bytes):
    if len(one_or_four_bytes) not in (1, 4):
        raise ValueError("provide one or four bytes")

    if len(one_or_four_bytes) == 1:
        return u8(one_or_four_bytes)

    return u32(one_or_four_bytes)


def string_index_to_offset(index, string_table):
    if index == len(string_table) - 1:
        return len(b"\x00".join(string_table)) - 1

    return len(b"\x00".join(string_table[: index + 1])) - len(string_table[index])


def offset_to_string_index(offset, string_table):
    raw_strings = get_raw_string_table(string_table)

    if offset == len(raw_strings) - 1:
        return len(raw_strings.split(b"\x00")) - 1
    return raw_strings[:offset].count(b"\x00")


def u8(byte):
    return struct.unpack("<B", byte)[0]


def u32(four_bytes_or_stream):
    if not isinstance(four_bytes_or_stream, bytes):
        four_bytes_or_stream = four_bytes_or_stream.read(U32_BYTES)

    if len(four_bytes_or_stream) != 4:
        raise ValueError("provide four bytes")

    return struct.unpack("<I", four_bytes_or_stream)[0]


def offset_to_string(offset, string_table):
    raw_string = get_raw_string_table(string_table)
    end = raw_string.index(b"\00", offset)

    return raw_string[offset:end]


def parse_protocol_version(stream):
    version = u32(stream)
    if version not in SUPPORTED_DSO_VERSIONS:
        raise ValueError(
            f"dso version {version} is not on supported list ({SUPPORTED_DSO_VERSIONS})"
        )

    return version


def parse_string_table(stream):
    strings_length = u32(stream)
    string_table = stream.read(strings_length).split(b"\x00")

    real_table = {}
    i = 0
    for entry in string_table:
        real_table[i] = entry
        if i > 0:  # hack to include the null bytes themselves
            real_table[i - 1] = b"\x00"
        i += len(entry) + 1

    return real_table


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("dso_file", help="Path to dso file")
    parsed_args = parser.parse_args(sys.argv[1:])
    with open(parsed_args.dso_file, "rb") as f:
        dso = DSO.from_stream(f)


if __name__ == "__main__":
    main()
