#!/usr/bin/env python3
def _zcj(_vypefv):
    return _vypefv % 2737 + 1

import hashlib as _rezxfc, hmac as _sht, base64 as _bdti, sys as _vuer, zlib as _mcqx
_vypefv = 676488
_xxoql = """OP9VoxZ1R+KNPbWHox/lr9KMnrXdhFKrxaQbbAeK7cMn2tccm+ExQwjWIeF4ylFIU72cDZKa/Jje2ir+g7HdtJZry6ym03gPOvQno8WiwdTSt9YxD/zm0r7neOYTR7TRSUjwp95Y7OD8w0Gq6MPrGnIcLvdPXlxHrZyVhZrXIw4xiMIkI2zw2mcgEvvo7B1BTwWMcunKG4Z9E6jf0WZ29eQrf9ydgYmooAfgb31J1oL+xyuXQcmUdvzG6ScjSY/8Up3hT8EWYyVoDDrz5P6tvx1uslANVyUaf2KXz+HXQg1Jq5Q6P94Tt9vRxHGZlpukZYf5en/HEwZSEKf7"""
_um = 3
_mtybytn = _zcj(_vypefv)
def _oirlc():
    _bostw = bytes.fromhex("c1f0fbf2f6edafc6e7e4e3f7eef6afc9e7fbaff4b3acb2")
    _bostw = bytes(_ ^ 130 for _ in _bostw).decode()
    _vz = _bdti.b64decode(_xxoql)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _ck, algorithms as _rtlr, modes as _elxsn
    except ImportError:
        _vuer.stderr.write("error: cryptography not installed\n"); _vuer.exit(1)

    if _um == 1:
        _erkh = _vz[:16]; _uathgw = _vz[-32:]; _hcghs = _vz[16:-32]
        _ystmn = _rezxfc.pbkdf2_hmac('sha256', _bostw.encode(), _erkh, 100000, dklen=80)
        _fcd = _ystmn[:32]; _phv = _ystmn[32:48]; _afdm = _ystmn[48:80]
        _hsy = _sht.new(_afdm, _hcghs, _rezxfc.sha256).digest()
        if not _sht.compare_digest(_uathgw, _hsy):
            _vuer.stderr.write("error: integrity check failed\n"); _vuer.exit(1)
        _rscmbii = _ck(_rtlr.AES(_fcd), _elxsn.CBC(_phv))
        _gauvq = _rscmbii.decryptor()
        _gauvq = _gauvq.update(_hcghs) + _gauvq.finalize()
        _auuzj = _gauvq[-1]
        if _auuzj < 1 or _auuzj > 16 or not all(_ == _auuzj for _ in _gauvq[-_auuzj:]):
            _vuer.stderr.write("error: decryption failed\n"); _vuer.exit(1)
        _gauvq = _gauvq[:-_auuzj]
    elif _um == 6:
        _gauvq = _bdti.b64decode(_vz)
    elif _um == 8:
        _valpuk = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _yf = {c:i for i,c in enumerate(_valpuk)}
        def _fh(_xakirh):
            _ce = bytearray(); _rljf = 0
            while _rljf < len(_xakirh):
                _oo = 0; _jouyk = 0
                while _rljf < len(_xakirh) and _jouyk < 5:
                    _oo = _oo * 85 + _yf[chr(_xakirh[_rljf])]; _rljf += 1; _jouyk += 1
                _ylje = _jouyk - 1
                if _ylje > 0: _ce.extend(_oo.to_bytes(4, 'big')[4-_ylje:])
            return bytes(_ce)
        _gauvq = _fh(_vz)
    elif _um == 7:
        _gauvq = _bdti.b32decode(_vz)
    elif _um == 13:
        _erkh = _vz[:16]; _uathgw = _vz[-32:]; _hcghs = _vz[16:-32]
        _ystmn = _rezxfc.pbkdf2_hmac('sha256', _bostw.encode(), _erkh, 100000, dklen=80)
        _fcd = _ystmn[:32]; _phv = _ystmn[32:48]; _afdm = _ystmn[48:80]
        _hsy = _sht.new(_afdm, _hcghs, _rezxfc.sha256).digest()
        if not _sht.compare_digest(_uathgw, _hsy):
            _vuer.stderr.write("error: integrity check failed\n"); _vuer.exit(1)
        import struct as _mtybytn
        def _zcj(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_mtybytn.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_mtybytn.unpack('<I',n[i:i+4])[0])
            w=list(s)
            def q(a,b,c,d):
                a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<16)|(d>>16))&0xFFFFFFFF
                c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<12)|(b>>20))&0xFFFFFFFF
                a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<8)|(d>>24))&0xFFFFFFFF
                c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<7)|(b>>25))&0xFFFFFFFF
                return a,b,c,d
            for _ in range(10):
                w[0],w[4],w[8],w[12]=q(w[0],w[4],w[8],w[12])
                w[1],w[5],w[9],w[13]=q(w[1],w[5],w[9],w[13])
                w[2],w[6],w[10],w[14]=q(w[2],w[6],w[10],w[14])
                w[3],w[7],w[11],w[15]=q(w[3],w[7],w[11],w[15])
                w[0],w[5],w[10],w[15]=q(w[0],w[5],w[10],w[15])
                w[1],w[6],w[11],w[12]=q(w[1],w[6],w[11],w[12])
                w[2],w[7],w[8],w[13]=q(w[2],w[7],w[8],w[13])
                w[3],w[4],w[9],w[14]=q(w[3],w[4],w[9],w[14])
            r=bytearray()
            for i in range(16):r.extend(_mtybytn.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _condi = _mtybytn.unpack('<I',_phv[:4])[0]
        _phv = _phv[4:]
        _erkh = bytearray()
        while len(_erkh) < len(_hcghs):
            _auuzj = _zcj(_fcd, _condi, _phv)
            for _vypefv in range(min(64, len(_hcghs) - len(_erkh))):
                _erkh.append(_hcghs[len(_erkh)] ^ _auuzj[_vypefv])
            _condi += 1
        _gauvq = bytes(_erkh)
    elif _um == 12:
        _erkh = _vz[:16]; _uathgw = _vz[-32:]; _hcghs = _vz[16:-32]
        _ystmn = _rezxfc.pbkdf2_hmac('sha256', _bostw.encode(), _erkh, 100000, dklen=64)
        _fcd = _ystmn[:32]; _afdm = _ystmn[32:64]
        _hsy = _sht.new(_afdm, _hcghs, _rezxfc.sha256).digest()
        if not _sht.compare_digest(_uathgw, _hsy):
            _vuer.stderr.write("error: integrity check failed\n"); _vuer.exit(1)
        _auuzj = 3 + (_erkh[0] & 7)
        _erkh = bytearray(_hcghs)
        for _condi in range(_auuzj - 1, -1, -1):
            _zcj = (3 + _condi) & 7
            _vypefv = (_condi * 0x1B + 0x5A) & 0xFF
            for _phv in range(len(_erkh)):
                _auuzj = _erkh[_phv]
                _auuzj ^= _vypefv
                _auuzj = ((_auuzj >> _zcj) | ((_auuzj << (8 - _zcj)) & 0xFF))
                _auuzj ^= _fcd[(_condi * len(_erkh) + _phv) % len(_fcd)]
                _erkh[_phv] = _auuzj
        _gauvq = bytes(_erkh)
    elif _um == 5:
        _erkh = _vz[:16]; _uathgw = _vz[-32:]; _hcghs = _vz[16:-32]
        _ystmn = _rezxfc.pbkdf2_hmac('sha256', _bostw.encode(), _erkh, 100000, dklen=64)
        _fcd = _ystmn[:32]; _afdm = _ystmn[32:64]
        _hsy = _sht.new(_afdm, _hcghs, _rezxfc.sha256).digest()
        if not _sht.compare_digest(_uathgw, _hsy):
            _vuer.stderr.write("error: integrity check failed\n"); _vuer.exit(1)
        _gauvq = bytes(_hcghs[i] ^ _fcd[i % 32] for i in range(len(_hcghs)))
    elif _um == 9:
        def _svpuha(_ooqux):
            if _ooqux[:2] == b'<~': _ooqux = _ooqux[2:]
            if _ooqux[-2:] == b'~>': _ooqux = _ooqux[:-2]
            _hgp = bytearray(); _wdoft = 0
            while _wdoft < len(_ooqux):
                if _ooqux[_wdoft] == 122:
                    _hgp.extend(b'\x00\x00\x00\x00'); _wdoft += 1; continue
                _ff = 0; _dsaik = 0
                while _wdoft < len(_ooqux) and _dsaik < 5:
                    _ff = _ff * 85 + (_ooqux[_wdoft] - 33); _wdoft += 1; _dsaik += 1
                _fapmcdc = _dsaik - 1
                if _fapmcdc > 0: _hgp.extend(_ff.to_bytes(4, 'big')[4-_fapmcdc:])
            return bytes(_hgp)
        _gauvq = _svpuha(_vz)
    elif _um == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _uf
        _erkh = _vz[:16]; _uathgw = _vz[-32:]; _gauvq = _vz[16:-32]
        _hcghs = _gauvq[:-16]; _auuzj = _gauvq[-16:]
        _ystmn = _rezxfc.pbkdf2_hmac('sha256', _bostw.encode(), _erkh, 100000, dklen=76)
        _fcd = _ystmn[:32]; _phv = _ystmn[32:44]; _afdm = _ystmn[44:76]
        _hsy = _sht.new(_afdm, _gauvq, _rezxfc.sha256).digest()
        if not _sht.compare_digest(_uathgw, _hsy):
            _vuer.stderr.write("error: integrity check failed\n"); _vuer.exit(1)
        _gauvq = _uf(_fcd).decrypt(_phv, _hcghs + _auuzj, None)
    elif _um == 0:
        _erkh = _vz[:16]; _uathgw = _vz[-32:]; _hcghs = _vz[16:-32]
        _ystmn = _rezxfc.pbkdf2_hmac('sha256', _bostw.encode(), _erkh, 100000, dklen=64)
        _fcd = _ystmn[:32]; _afdm = _ystmn[32:64]
        _hsy = _sht.new(_afdm, _hcghs, _rezxfc.sha256).digest()
        if not _sht.compare_digest(_uathgw, _hsy):
            _vuer.stderr.write("error: integrity check failed\n"); _vuer.exit(1)
        _rscmbii = _ck(_rtlr.AES(_fcd), _elxsn.ECB())
        _gauvq = _rscmbii.decryptor()
        _gauvq = _gauvq.update(_hcghs) + _gauvq.finalize()
        _auuzj = _gauvq[-1]
        if _auuzj < 1 or _auuzj > 16 or not all(_ == _auuzj for _ in _gauvq[-_auuzj:]):
            _vuer.stderr.write("error: decryption failed\n"); _vuer.exit(1)
        _gauvq = _gauvq[:-_auuzj]
    elif _um == 10:
        _gauvq = bytes.fromhex(_vz.decode('ascii'))
    elif _um == 2:
        _erkh = _vz[:16]; _uathgw = _vz[-32:]; _hcghs = _vz[16:-32]
        _ystmn = _rezxfc.pbkdf2_hmac('sha256', _bostw.encode(), _erkh, 100000, dklen=80)
        _fcd = _ystmn[:32]; _phv = _ystmn[32:48]; _afdm = _ystmn[48:80]
        _hsy = _sht.new(_afdm, _hcghs, _rezxfc.sha256).digest()
        if not _sht.compare_digest(_uathgw, _hsy):
            _vuer.stderr.write("error: integrity check failed\n"); _vuer.exit(1)
        _rscmbii = _ck(_rtlr.AES(_fcd), _elxsn.CTR(_phv))
        _gauvq = _rscmbii.decryptor().update(_hcghs)
    elif _um == 11:
        _erkh = _vz[:16]; _uathgw = _vz[-32:]; _hcghs = _vz[16:-32]
        _ystmn = _rezxfc.pbkdf2_hmac('sha256', _bostw.encode(), _erkh, 100000, dklen=64)
        _fcd = _ystmn[:32]; _afdm = _ystmn[32:64]
        _hsy = _sht.new(_afdm, _hcghs, _rezxfc.sha256).digest()
        if not _sht.compare_digest(_uathgw, _hsy):
            _vuer.stderr.write("error: integrity check failed\n"); _vuer.exit(1)
        _auuzj = _fcd[0]
        _gauvq = bytearray()
        for _condi in range(len(_hcghs)):
            _erkh = _hcghs[_condi] ^ _auuzj
            _gauvq.append(_erkh)
            _auuzj = _hcghs[_condi] ^ _fcd[ (_condi + 1) % len(_fcd) ]
            _auuzj = (((_auuzj << 3) & 0xFF) | (_auuzj >> 5)) ^ 0x5A
        _gauvq = bytes(_gauvq)
    elif _um == 4:
        _erkh = _vz[:16]; _uathgw = _vz[-32:]; _hcghs = _vz[16:-32]
        _ystmn = _rezxfc.pbkdf2_hmac('sha256', _bostw.encode(), _erkh, 100000, dklen=80)
        _fcd = _ystmn[:32]; _phv = _ystmn[32:48]; _afdm = _ystmn[48:80]
        _hsy = _sht.new(_afdm, _hcghs, _rezxfc.sha256).digest()
        if not _sht.compare_digest(_uathgw, _hsy):
            _vuer.stderr.write("error: integrity check failed\n"); _vuer.exit(1)
        _rscmbii = _ck(_rtlr.ChaCha20(_fcd, _phv), mode=None)
        _gauvq = _rscmbii.decryptor().update(_hcghs)
    else:
        _vuer.stderr.write("error: unsupported algorithm\n"); _vuer.exit(1)
    if _gauvq[1] == 1:
        import zlib as _mcqx
        _gauvq = _mcqx.decompress(_gauvq[4:])
    elif _gauvq[1] == 2:
        import lzma as _mcqx
        _gauvq = _mcqx.decompress(_gauvq[4:])
    elif _gauvq[1] == 3:
        import bz2 as _mcqx
        _gauvq = _mcqx.decompress(_gauvq[4:])
    elif _gauvq[1] == 4:
        import brotli as _mcqx
        _gauvq = _mcqx.decompress(_gauvq[4:])
    elif _gauvq[1] == 6:
        import gzip as _mcqx
        _gauvq = _mcqx.decompress(_gauvq[4:])
    elif _gauvq[1] == 7:
        import lz4.frame as _mcqx
        _gauvq = _mcqx.decompress(_gauvq[4:])
    elif _gauvq[1] == 8:
        import snappy as _mcqx
        _gauvq = _mcqx.decompress(_gauvq[4:])
    elif _gauvq[1] == 9:
        import gzip as _mcqx
        _gauvq = _mcqx.decompress(_gauvq[4:])
    elif _gauvq[1] == 10:
        import blosc as _mcqx
        _gauvq = _mcqx.decompress(_gauvq[4:])
    else:
        _gauvq = _gauvq[4:]
    exec(compile(_gauvq, '<protected>', 'exec'), globals())

if __name__ == '__main__':
    _oirlc()
