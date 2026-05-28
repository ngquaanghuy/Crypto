#ifndef CRYPTO_VM_INTERP_PY_H
#define CRYPTO_VM_INTERP_PY_H

// Python VM interpreter — embedded in generated stub
static const char VM_INTERP_SCRIPT[] = R"vm_interp(
def _vm_run(_code, _consts, _names, _globals, _locals):
    _r = [None] * 64
    _ip = 0
    _n = len(_code)
    _b = __builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__
    while _ip < _n:
        _op = _code[_ip]
        _rd = _code[_ip + 1]
        _rs1 = _code[_ip + 2]
        _rs2 = _code[_ip + 3]
        _imm = _code[_ip + 4] | (_code[_ip + 5] << 8) | (_code[_ip + 6] << 16) | (_code[_ip + 7] << 24)
        if _op == 0:
            pass
        elif _op == 1:
            _r[_rd] = _consts[_imm]
        elif _op == 2:
            _nm = _names[_imm]
            _r[_rd] = _globals.get(_nm) if _nm in _globals else _b.get(_nm, _nm)
        elif _op == 3:
            _globals[_names[_imm]] = _r[_rd]
        elif _op == 4:
            _r[_rd] = _locals.get(_names[_imm], None)
        elif _op == 5:
            _locals[_names[_imm]] = _r[_rd]
        elif _op == 6:
            _r[_rd] = _r[_rs1]
        elif _op == 60:
            _r[_rd] = getattr(_r[_rs1], _names[_imm])
        elif _op == 61:
            _r[_rd] = __import__(_names[_imm])
        elif _op == 10:
            _r[_rd] = _r[_rs1] + _r[_rs2]
        elif _op == 11:
            _r[_rd] = _r[_rs1] - _r[_rs2]
        elif _op == 12:
            _r[_rd] = _r[_rs1] * _r[_rs2]
        elif _op == 13:
            _r[_rd] = _r[_rs1] / _r[_rs2]
        elif _op == 14:
            _r[_rd] = _r[_rs1] ** _r[_rs2]
        elif _op == 15:
            _r[_rd] = -_r[_rs1]
        elif _op == 20:
            _r[_rd] = _r[_rs1] == _r[_rs2]
        elif _op == 21:
            _r[_rd] = _r[_rs1] != _r[_rs2]
        elif _op == 22:
            _r[_rd] = _r[_rs1] < _r[_rs2]
        elif _op == 23:
            _r[_rd] = _r[_rs1] <= _r[_rs2]
        elif _op == 24:
            _r[_rd] = _r[_rs1] > _r[_rs2]
        elif _op == 25:
            _r[_rd] = _r[_rs1] >= _r[_rs2]
        elif _op == 30:
            _ip = _imm * 8
            continue
        elif _op == 31:
            if _r[_rd]:
                _ip = _imm * 8
            else:
                _ip += 8
            continue
        elif _op == 32:
            if not _r[_rd]:
                _ip = _imm * 8
            else:
                _ip += 8
            continue
        elif _op == 33:
            _r[_rd] = _r[_rs1][_r[_rs2]]
        elif _op == 50:
            _r[_rs1][_r[_rs2]] = _r[_rd]
        elif _op == 40:
            _fn = _r[_rs1]
            _args = tuple(_r[_rs1 + 1 + _i] for _i in range(_imm & 0xFFFF))
            _r[_rd] = _fn(*_args)
        elif _op == 41:
            _r[_rd] = _names[_rd](*_r[_rs1:_rs1 + (_imm & 0xFFFF)])
        elif _op == 42:
            return _r[_rd]
        elif _op == 43:
            _r[_rd] = tuple(_r[_rs1:_rs1 + _rs2])
        elif _op == 44:
            _r[_rd] = list(_r[_rs1:_rs1 + _rs2])
        elif _op == 62:
            _r[_rd] = str(_r[_rs1])
        elif _op == 63:
            _r[_rd] = ''.join(str(_r[_rs1 + _i]) for _i in range(_rs2))
        elif _op == 70:
            _r[_rd] = iter(_r[_rs1])
        elif _op == 71:
            try:
                _r[_rd] = next(_r[_rs1])
            except StopIteration:
                _ip = _imm * 8
                continue
        elif _op == 72:
            _r[_rd].extend(_r[_rs1])
        elif _op == 75:
            _r[_rd].append(_r[_rs1])
        elif _op == 52:
            _v = _r[_rs1]
            try:
                if _imm == 0:
                    if not (_v + 1 == _v): pass
                elif _imm == 1:
                    if not (_v != _v): pass
                else:
                    if not (_v - 1 == _v): pass
            except TypeError:
                pass
        elif _op == 53:
            _v = _r[_rs1]
            try:
                if _imm == 0:
                    if _v * 0 != 0: pass
                elif _imm == 1:
                    if _v != _v: pass
                else:
                    if _v + 1 == _v: pass
            except TypeError:
                pass
        _ip += 8

def _vm_deserialize(_data):
    _pos = 0
    _hl = int.from_bytes(_data[_pos:_pos+4], 'little'); _pos += 4
    _hot = _data[_pos:_pos+_hl].decode('utf-8'); _pos += _hl
    _cc = int.from_bytes(_data[_pos:_pos+4], 'little'); _pos += 4
    _consts = []
    for _ in range(_cc):
        _t = _data[_pos]; _pos += 1
        _sl = int.from_bytes(_data[_pos:_pos+4], 'little'); _pos += 4
        _s = _data[_pos:_pos+_sl]; _pos += _sl
        if _t == 0: _v = None
        elif _t == 1: _v = _s == b'1'
        elif _t == 2: _v = int(_s)
        elif _t == 3: _v = float(_s)
        elif _t == 4: _v = _s.decode('utf-8')
        elif _t == 6: _v = eval(_s)
        elif _t == 7: _v = _s
        elif _t == 8: _v = eval(_s)
        else: _v = _s
        _consts.append(_v)
    _nc = int.from_bytes(_data[_pos:_pos+4], 'little'); _pos += 4
    _names = []
    for _ in range(_nc):
        _nl = int.from_bytes(_data[_pos:_pos+2], 'little'); _pos += 2
        _names.append(_data[_pos:_pos+_nl].decode('utf-8')); _pos += _nl
    _ic = int.from_bytes(_data[_pos:_pos+4], 'little'); _pos += 4
    _code = _data[_pos:_pos+_ic*8]
    return _hot, _code, _consts, _names
)vm_interp";
#endif
