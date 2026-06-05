#!/usr/bin/env python3
def _rrm(_py):
    return _py % 5527 + 1

import hashlib as _hhks, hmac as _hgcyl, base64 as _fkhp, sys as _cvy, zlib as _cqvrp
_py = 286276
_rhmp = """UMkdK+TQxfZ1+3TxbJZ3WwOIIYpfY+uOGo6RVyT+JIxq+DEHXSl/91RjF+kX2EwzUfUtw1m5tS5pm9aXpOiXx4YG7ANUm5g3wriCchThcpPvbQBe8zT0QFTKZbqj3/E05ylrfoQjB67rr6BNIwb/ANkMpikL24iEQHAZFh59Q+ZYp5SJx/qjc5nr1IFV8jYEesvtklvdlYTF5f00vChH9qD7R3KcyoKCjdxdvM2BX6Ov1kc4XnEyNt+ePHC/8ly0n70+sKgtSU4KT2yQR7wLh2iMolc/orI698riUnJ/jUNNIcWN0z7lusRt0EcwTnHR8sVrYXjGIU7hD60xW3znyvzv9hlo3X5uxxUskojlO1KGBtlBITbcV6QmVp9YYXCcE0DQoy91S0Zyga3bmMypVbbx+n88SNSlY3MXLOZy8ewIbTOva4D2S8WaMQZLTERCDDcTeZ3CIM8iZz7u+lK3I2hlTZs/iO6acyq8"""
_vyoplv = 3
_tgmxfec = _rrm(_py)
def _xqhc():
    _pvlj = bytes.fromhex("958385948392")
    _pvlj = bytes(_ ^ 230 for _ in _pvlj).decode()
    _vss = _fkhp.b64decode(_rhmp)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _gerp, algorithms as _nvbkun, modes as _eewvm
    except ImportError:
        _cvy.stderr.write("error: cryptography not installed\n"); _cvy.exit(1)

    if _vyoplv == 4:
        _zy = _vss[:16]; _arqo = _vss[-32:]; _pidww = _vss[16:-32]
        _dmhth = _hhks.pbkdf2_hmac('sha256', _pvlj.encode(), _zy, 100000, dklen=80)
        _ekpxda = _dmhth[:32]; _vh = _dmhth[32:48]; _ni = _dmhth[48:80]
        _yx = _hgcyl.new(_ni, _pidww, _hhks.sha256).digest()
        if not _hgcyl.compare_digest(_arqo, _yx):
            _cvy.stderr.write("error: integrity check failed\n"); _cvy.exit(1)
        _bwftw = _gerp(_nvbkun.ChaCha20(_ekpxda, _vh), mode=None)
        _llipxri = _bwftw.decryptor().update(_pidww)
    elif _vyoplv == 12:
        _zy = _vss[:16]; _arqo = _vss[-32:]; _pidww = _vss[16:-32]
        _dmhth = _hhks.pbkdf2_hmac('sha256', _pvlj.encode(), _zy, 100000, dklen=64)
        _ekpxda = _dmhth[:32]; _ni = _dmhth[32:64]
        _yx = _hgcyl.new(_ni, _pidww, _hhks.sha256).digest()
        if not _hgcyl.compare_digest(_arqo, _yx):
            _cvy.stderr.write("error: integrity check failed\n"); _cvy.exit(1)
        _lora = 3 + (_zy[0] & 7)
        _zy = bytearray(_pidww)
        for _gavior in range(_lora - 1, -1, -1):
            _rrm = (3 + _gavior) & 7
            _py = (_gavior * 0x1B + 0x5A) & 0xFF
            for _vh in range(len(_zy)):
                _lora = _zy[_vh]
                _lora ^= _py
                _lora = ((_lora >> _rrm) | ((_lora << (8 - _rrm)) & 0xFF))
                _lora ^= _ekpxda[(_gavior * len(_zy) + _vh) % len(_ekpxda)]
                _zy[_vh] = _lora
        _llipxri = bytes(_zy)
    elif _vyoplv == 1:
        _zy = _vss[:16]; _arqo = _vss[-32:]; _pidww = _vss[16:-32]
        _dmhth = _hhks.pbkdf2_hmac('sha256', _pvlj.encode(), _zy, 100000, dklen=80)
        _ekpxda = _dmhth[:32]; _vh = _dmhth[32:48]; _ni = _dmhth[48:80]
        _yx = _hgcyl.new(_ni, _pidww, _hhks.sha256).digest()
        if not _hgcyl.compare_digest(_arqo, _yx):
            _cvy.stderr.write("error: integrity check failed\n"); _cvy.exit(1)
        _bwftw = _gerp(_nvbkun.AES(_ekpxda), _eewvm.CBC(_vh))
        _llipxri = _bwftw.decryptor()
        _llipxri = _llipxri.update(_pidww) + _llipxri.finalize()
        _lora = _llipxri[-1]
        if _lora < 1 or _lora > 16 or not all(_ == _lora for _ in _llipxri[-_lora:]):
            _cvy.stderr.write("error: decryption failed\n"); _cvy.exit(1)
        _llipxri = _llipxri[:-_lora]
    elif _vyoplv == 8:
        _xiu = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _ooqvg = {c:i for i,c in enumerate(_xiu)}
        def _btccf(_pe):
            _va = bytearray(); _hfh = 0
            while _hfh < len(_pe):
                _aq = 0; _ubze = 0
                while _hfh < len(_pe) and _ubze < 5:
                    _aq = _aq * 85 + _ooqvg[chr(_pe[_hfh])]; _hfh += 1; _ubze += 1
                _htkzoqg = _ubze - 1
                if _htkzoqg > 0: _va.extend(_aq.to_bytes(4, 'big')[4-_htkzoqg:])
            return bytes(_va)
        _llipxri = _btccf(_vss)
    elif _vyoplv == 10:
        _llipxri = bytes.fromhex(_vss.decode('ascii'))
    elif _vyoplv == 6:
        _llipxri = _fkhp.b64decode(_vss)
    elif _vyoplv == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _wajrjie
        _zy = _vss[:16]; _arqo = _vss[-32:]; _llipxri = _vss[16:-32]
        _pidww = _llipxri[:-16]; _lora = _llipxri[-16:]
        _dmhth = _hhks.pbkdf2_hmac('sha256', _pvlj.encode(), _zy, 100000, dklen=76)
        _ekpxda = _dmhth[:32]; _vh = _dmhth[32:44]; _ni = _dmhth[44:76]
        _yx = _hgcyl.new(_ni, _llipxri, _hhks.sha256).digest()
        if not _hgcyl.compare_digest(_arqo, _yx):
            _cvy.stderr.write("error: integrity check failed\n"); _cvy.exit(1)
        _llipxri = _wajrjie(_ekpxda).decrypt(_vh, _pidww + _lora, None)
    elif _vyoplv == 5:
        _zy = _vss[:16]; _arqo = _vss[-32:]; _pidww = _vss[16:-32]
        _dmhth = _hhks.pbkdf2_hmac('sha256', _pvlj.encode(), _zy, 100000, dklen=64)
        _ekpxda = _dmhth[:32]; _ni = _dmhth[32:64]
        _yx = _hgcyl.new(_ni, _pidww, _hhks.sha256).digest()
        if not _hgcyl.compare_digest(_arqo, _yx):
            _cvy.stderr.write("error: integrity check failed\n"); _cvy.exit(1)
        _llipxri = bytes(_pidww[i] ^ _ekpxda[i % 32] for i in range(len(_pidww)))
    elif _vyoplv == 2:
        _zy = _vss[:16]; _arqo = _vss[-32:]; _pidww = _vss[16:-32]
        _dmhth = _hhks.pbkdf2_hmac('sha256', _pvlj.encode(), _zy, 100000, dklen=80)
        _ekpxda = _dmhth[:32]; _vh = _dmhth[32:48]; _ni = _dmhth[48:80]
        _yx = _hgcyl.new(_ni, _pidww, _hhks.sha256).digest()
        if not _hgcyl.compare_digest(_arqo, _yx):
            _cvy.stderr.write("error: integrity check failed\n"); _cvy.exit(1)
        _bwftw = _gerp(_nvbkun.AES(_ekpxda), _eewvm.CTR(_vh))
        _llipxri = _bwftw.decryptor().update(_pidww)
    elif _vyoplv == 9:
        def _llt(_jlxqgyp):
            if _jlxqgyp[:2] == b'<~': _jlxqgyp = _jlxqgyp[2:]
            if _jlxqgyp[-2:] == b'~>': _jlxqgyp = _jlxqgyp[:-2]
            _fxcfpe = bytearray(); _qdenm = 0
            while _qdenm < len(_jlxqgyp):
                if _jlxqgyp[_qdenm] == 122:
                    _fxcfpe.extend(b'\x00\x00\x00\x00'); _qdenm += 1; continue
                _xnp = 0; _uibfd = 0
                while _qdenm < len(_jlxqgyp) and _uibfd < 5:
                    _xnp = _xnp * 85 + (_jlxqgyp[_qdenm] - 33); _qdenm += 1; _uibfd += 1
                _qotgxr = _uibfd - 1
                if _qotgxr > 0: _fxcfpe.extend(_xnp.to_bytes(4, 'big')[4-_qotgxr:])
            return bytes(_fxcfpe)
        _llipxri = _llt(_vss)
    elif _vyoplv == 11:
        _zy = _vss[:16]; _arqo = _vss[-32:]; _pidww = _vss[16:-32]
        _dmhth = _hhks.pbkdf2_hmac('sha256', _pvlj.encode(), _zy, 100000, dklen=64)
        _ekpxda = _dmhth[:32]; _ni = _dmhth[32:64]
        _yx = _hgcyl.new(_ni, _pidww, _hhks.sha256).digest()
        if not _hgcyl.compare_digest(_arqo, _yx):
            _cvy.stderr.write("error: integrity check failed\n"); _cvy.exit(1)
        _lora = _ekpxda[0]
        _llipxri = bytearray()
        for _gavior in range(len(_pidww)):
            _zy = _pidww[_gavior] ^ _lora
            _llipxri.append(_zy)
            _lora = _pidww[_gavior] ^ _ekpxda[ (_gavior + 1) % len(_ekpxda) ]
            _lora = (((_lora << 3) & 0xFF) | (_lora >> 5)) ^ 0x5A
        _llipxri = bytes(_llipxri)
    elif _vyoplv == 7:
        _llipxri = _fkhp.b32decode(_vss)
    elif _vyoplv == 0:
        _zy = _vss[:16]; _arqo = _vss[-32:]; _pidww = _vss[16:-32]
        _dmhth = _hhks.pbkdf2_hmac('sha256', _pvlj.encode(), _zy, 100000, dklen=64)
        _ekpxda = _dmhth[:32]; _ni = _dmhth[32:64]
        _yx = _hgcyl.new(_ni, _pidww, _hhks.sha256).digest()
        if not _hgcyl.compare_digest(_arqo, _yx):
            _cvy.stderr.write("error: integrity check failed\n"); _cvy.exit(1)
        _bwftw = _gerp(_nvbkun.AES(_ekpxda), _eewvm.ECB())
        _llipxri = _bwftw.decryptor()
        _llipxri = _llipxri.update(_pidww) + _llipxri.finalize()
        _lora = _llipxri[-1]
        if _lora < 1 or _lora > 16 or not all(_ == _lora for _ in _llipxri[-_lora:]):
            _cvy.stderr.write("error: decryption failed\n"); _cvy.exit(1)
        _llipxri = _llipxri[:-_lora]
    else:
        _cvy.stderr.write("error: unsupported algorithm\n"); _cvy.exit(1)
    if _llipxri[1] == 1:
        import zlib as _cqvrp
        _llipxri = _cqvrp.decompress(_llipxri[4:])
    elif _llipxri[1] == 2:
        import lzma as _cqvrp
        _llipxri = _cqvrp.decompress(_llipxri[4:])
    elif _llipxri[1] == 3:
        import bz2 as _cqvrp
        _llipxri = _cqvrp.decompress(_llipxri[4:])
    elif _llipxri[1] == 4:
        import brotli as _cqvrp
        _llipxri = _cqvrp.decompress(_llipxri[4:])
    elif _llipxri[1] == 6:
        import gzip as _cqvrp
        _llipxri = _cqvrp.decompress(_llipxri[4:])
    elif _llipxri[1] == 7:
        import lz4.frame as _cqvrp
        _llipxri = _cqvrp.decompress(_llipxri[4:])
    elif _llipxri[1] == 8:
        import snappy as _cqvrp
        _llipxri = _cqvrp.decompress(_llipxri[4:])
    elif _llipxri[1] == 9:
        import gzip as _cqvrp
        _llipxri = _cqvrp.decompress(_llipxri[4:])
    elif _llipxri[1] == 10:
        import blosc as _cqvrp
        _llipxri = _cqvrp.decompress(_llipxri[4:])
    else:
        _llipxri = _llipxri[4:]
    exec(compile(_llipxri, '<protected>', 'exec'), globals())

if __name__ == '__main__':
    _xqhc()
