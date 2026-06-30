#include "cli/protect_internal.h"
#include <openssl/evp.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <format>
#include <string>
#include <vector>
#include <string_view>

namespace protect {

static const char ANTI_DEBUG_CODE_ARR[] =
    "    if __S__.gettrace() is not None:\n"
    "        __S__.stderr.write('error: debugger detected\\n'); __S__.exit(1)\n"
    "    __S__.breakpointhook = None\n"
    "    __S__.settrace(None); __S__.setprofile(None)\n"
    "    for __m in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):\n"
    "        if __m in __S__.modules:\n"
    "            __S__.stderr.write('error: debugger detected\\n'); __S__.exit(1)\n"
    "    try:\n"
    "        import time as _T\n"
    "        _T1 = _T.perf_counter()\n"
    "        _ = [i for i in range(2000)]\n"
    "        _T2 = _T.perf_counter()\n"
    "        if _T2 - _T1 > 5.0:\n"
    "            __S__.stderr.write('error: slowdown detected\\n'); __S__.exit(1)\n"
    "    except: pass\n"
    "    try:\n"
    "        _EH = type(getattr(__S__, 'excepthook', None))\n"
    "        if _EH.__name__ != 'builtin_function_or_method':\n"
    "            __S__.stderr.write('error: exception hook tampered\\n'); __S__.exit(1)\n"
    "    except: pass\n"
    "    try:\n"
    "        import socket\n"
    "        _s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "        _s2.settimeout(1.0)\n"
    "        if _s2.connect_ex(('127.0.0.1', 5678)) == 0:\n"
    "            _s2.close(); __S__.stderr.write('error: debugger port detected\\n'); __S__.exit(1)\n"
    "        _s2.close()\n"
    "    except: pass\n";

static const char ANTI_FRIDA_CODE_ARR[] =
    "    if 'frida' in __S__.modules:\n"
    "        __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n"
    "    import os\n"
    "    if os.environ.get('FRIDA_SCRIPT'):\n"
    "        __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n"
    "    try:\n"
    "        import socket\n"
    "        _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "        _s.settimeout(1.0)\n"
    "        if _s.connect_ex(('127.0.0.1', 27042)) == 0:\n"
    "            _s.close(); __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n"
    "        _s.close()\n"
    "    except: pass\n"
    "    try:\n"
    "        for _f in ('maps','status','cmdline'):\n"
    "            with open('/proc/self/' + _f) as _fh:\n"
    "                if 'frida' in _fh.read():\n"
    "                    __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n"
    "    except: pass\n"
    "    try:\n"
    "        import gc\n"
    "        for _O in gc.get_objects():\n"
    "            _TN = type(_O).__name__\n"
    "            if 'frida' in _TN.lower() or 'instrument' in _TN.lower():\n"
    "                __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n"
    "    except: pass\n";

static const char ANTI_HOOK_CODE_ARR[] =
    "    import os as _HO\n"
    "    _BU = __S__.modules.get('builtins')\n"
    "    for _n in ('__import__','compile','exec','eval','open'):\n"
    "        _f = getattr(_BU, _n, None)\n"
    "        if _f is None: __S__.stderr.write('error: hook detected\\n'); __S__.exit(1)\n"
    "        _g = getattr(_f, '__name__', '')\n"
    "        if _g != _n: __S__.stderr.write('error: hook detected\\n'); __S__.exit(1)\n"
    "    _bt = type(getattr(_BU, '__build_class__', None))\n"
    "    if _bt.__name__ != 'builtin_function_or_method':\n"
    "        __S__.stderr.write('error: builtin tampering detected\\n'); __S__.exit(1)\n"
    "    _st = type(getattr(__S__, 'settrace', None))\n"
    "    if _st.__name__ != 'builtin_function_or_method':\n"
    "        __S__.stderr.write('error: sys tampering detected\\n'); __S__.exit(1)\n"
    "    _eh_t = type(getattr(__S__, 'excepthook', None))\n"
    "    if _eh_t.__name__ != 'builtin_function_or_method':\n"
    "        __S__.stderr.write('error: exception hook tampered\\n'); __S__.exit(1)\n"
    "    _uh_t = type(getattr(__S__, 'unraisablehook', None))\n"
    "    if _uh_t.__name__ != 'builtin_function_or_method':\n"
    "        __S__.stderr.write('error: unraisable hook tampered\\n'); __S__.exit(1)\n"
    "    for _ev in ('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT','LD_DEBUG',\n"
    "                'LD_OPENCL_LIBRARY_PATH','DYLD_INSERT_LIBRARIES',\n"
    "                'DYLD_LIBRARY_PATH','DYLD_FORCE_FLAT_NAMESPACE'):\n"
    "        if _HO.environ.get(_ev):\n"
    "            __S__.stderr.write('error: injection detected\\n'); __S__.exit(1)\n"
    "    _tr = __S__.gettrace()\n"
    "    if _tr is not None:\n"
    "        __S__.stderr.write('error: tracer detected\\n'); __S__.exit(1)\n"
    "    __S__.settrace(None); __S__.setprofile(None)\n"
    "    if getattr(__S__, 'platform', '') == 'linux':\n"
    "        try:\n"
    "            with open('/proc/self/maps') as _M:\n"
    "                for _L in _M:\n"
    "                    if 'rwx' in _L and '[' not in _L: __S__.stderr.write('error: WX memory detected\\n'); __S__.exit(1)\n"
    "                    if any(x in _L for x in ('/tmp/','/dev/shm/','hook','intercept')): __S__.stderr.write('error: hook injection detected\\n'); __S__.exit(1)\n"
    "        except: pass\n"
    "    if len(__S__.meta_path) > 5:\n"
    "        __S__.stderr.write('error: import hook detected\\n'); __S__.exit(1)\n"
    "    if getattr(__S__, 'flags', None) and __S__.flags.no_user_site:\n"
    "        __S__.stderr.write('error: sandbox detected\\n'); __S__.exit(1)\n"
    "    try:\n"
    "        import gc\n"
    "        for _O in gc.get_objects():\n"
    "            _TN = type(_O).__name__\n"
    "            if _TN in ('PyDevdFrame','Debugger','Tracer','Profiler','Hook'):\n"
    "                __S__.stderr.write('error: debugger object detected\\n'); __S__.exit(1)\n"
    "    except: pass\n"
    "    try:\n"
    "        import gc as _GC\n"
    "        _MODS = {_O.__name__ for _O in _GC.get_objects() if hasattr(_O, '__name__')}\n"
    "        for _DBG in ('pydevd','pdb','ipdb','frida'):\n"
    "            if _DBG in _MODS:\n"
    "                __S__.stderr.write('error: debugger module detected\\n'); __S__.exit(1)\n"
    "    except: pass\n";

static const char ANTI_INLINE_HOOK_CODE_ARR[] =
    "    if __S__.platform == 'linux':\n"
    "        try:\n"
    "            import ctypes as _CT\n"
    "            _LIBC = _CT.CDLL('libc.so.6')\n"
    "            for _FN in ('open', 'read', 'write', 'execve', 'system', 'popen'):\n"
    "                try:\n"
    "                    _ADDR = getattr(_LIBC, _FN)\n"
    "                    _PRO = bytes(_CT.c_ubyte.from_address(_ADDR + _I) for _I in range(12))\n"
    "                    if len(_PRO) >= 12:\n"
    "                        if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n"
    "                            __S__.stderr.write('error: inline hook detected\\n'); __S__.exit(1)\n"
    "                except: pass\n"
    "        except: pass\n"
    "        try:\n"
    "            with open('/proc/self/maps') as _M:\n"
    "                _WX = 0\n"
    "                for _L in _M:\n"
    "                    if ' rwx ' in _L or ' rwxp' in _L:\n"
    "                        if '[heap]' in _L or '[anon' in _L:\n"
    "                            _WX += 1\n"
    "                if _WX > 2:\n"
    "                    __S__.stderr.write('error: suspicious memory detected\\n'); __S__.exit(1)\n"
    "        except: pass\n"
    "    elif __S__.platform == 'win32':\n"
    "        try:\n"
    "            import ctypes as _CT\n"
    "            _K32 = _CT.windll.kernel32\n"
    "            _NTDLL = _CT.WinDLL('ntdll.dll')\n"
    "            for _FN in ('OpenProcess', 'ReadProcessMemory', 'WriteProcessMemory',\n"
    "                        'CreateRemoteThread', 'VirtualProtectEx', 'CreateProcessA'):\n"
    "                try:\n"
    "                    _ADDR = getattr(_K32, _FN)\n"
    "                    _PRO = bytes(_CT.c_ubyte.from_address(_ADDR + _I) for _I in range(12))\n"
    "                    if len(_PRO) >= 12:\n"
    "                        if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n"
    "                            __S__.stderr.write('error: inline hook detected\\n'); __S__.exit(1)\n"
    "                        if _PRO[0] == 0xE9:\n"
    "                            __S__.stderr.write('error: detours hook detected\\n'); __S__.exit(1)\n"
    "                        if _PRO[0] == 0x68 and _PRO[5] == 0xC3:\n"
    "                            __S__.stderr.write('error: push-ret hook detected\\n'); __S__.exit(1)\n"
    "                except: pass\n"
    "            for _FN in ('NtOpenProcess', 'NtReadVirtualMemory', 'NtWriteVirtualMemory',\n"
    "                        'NtCreateThreadEx', 'NtProtectVirtualMemory', 'NtAllocateVirtualMemory'):\n"
    "                try:\n"
    "                    _ADDR = getattr(_NTDLL, _FN)\n"
    "                    _PRO = bytes(_CT.c_ubyte.from_address(_ADDR + _I) for _I in range(12))\n"
    "                    if len(_PRO) >= 12:\n"
    "                        if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n"
    "                            __S__.stderr.write('error: ntdll inline hook detected\\n'); __S__.exit(1)\n"
    "                        if _PRO[0] == 0xE9:\n"
    "                            __S__.stderr.write('error: ntdll detours hook detected\\n'); __S__.exit(1)\n"
    "                except: pass\n"
    "        except: pass\n"
    "    elif __S__.platform == 'darwin':\n"
    "        try:\n"
    "            import ctypes as _CT\n"
    "            try:\n"
    "                _LIBC = _CT.CDLL('/usr/lib/libSystem.B.dylib')\n"
    "            except:\n"
    "                try:\n"
    "                    _LIBC = _CT.CDLL('/usr/lib/libSystem.dylib')\n"
    "                except:\n"
    "                    _LIBC = None\n"
    "            if _LIBC:\n"
    "                for _FN in ('open', 'read', 'write', 'execve', 'socket', 'connect'):\n"
    "                    try:\n"
    "                        _ADDR = getattr(_LIBC, _FN)\n"
    "                        _PRO = bytes(_CT.c_ubyte.from_address(_ADDR + _I) for _I in range(12))\n"
    "                        if len(_PRO) >= 12:\n"
    "                            if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n"
    "                                __S__.stderr.write('error: inline hook detected\\n'); __S__.exit(1)\n"
    "                            if _PRO[0] == 0xE9:\n"
    "                                __S__.stderr.write('error: detours hook detected\\n'); __S__.exit(1)\n"
    "                            if _PRO[0] == 0xFF and (_PRO[1] == 0x25 or _PRO[1] == 0x35):\n"
    "                                __S__.stderr.write('error: jmp hook detected\\n'); __S__.exit(1)\n"
    "                    except: pass\n"
    "        except: pass\n";

static const char ANTI_PLT_HOOK_CODE_ARR[] =
    "    if __S__.platform == 'linux':\n"
    "        try:\n"
    "            import struct as _ST\n"
    "            import ctypes as _CT\n"
    "            _LIBS = {}\n"
    "            _WX_ANON = 0\n"
    "            with open('/proc/self/maps') as _M:\n"
    "                for _L in _M:\n"
    "                    _P = _L.split()\n"
    "                    if len(_P) < 5: continue\n"
    "                    _R = _P[0].split('-')\n"
    "                    if len(_R) != 2: continue\n"
    "                    _S = int(_R[0], 16); _E = int(_R[1], 16)\n"
    "                    _PERMS = _P[1]; _PATH = _P[-1] if len(_P) >= 6 else ''\n"
    "                    if '.so' in _PATH:\n"
    "                        if _PATH not in _LIBS: _LIBS[_PATH] = []\n"
    "                        _LIBS[_PATH].append((_S, _E, _PERMS))\n"
    "                    if 'rwx' in _PERMS and '.so' not in _PATH and '[' not in _PATH:\n"
    "                        _WX_ANON += 1\n"
    "            if _WX_ANON > 2:\n"
    "                __S__.stderr.write('error: PLT/GOT hook detected\\n'); __S__.exit(1)\n"
    "            for _LIB in _LIBS:\n"
    "                if any(x in _LIB for x in ['/tmp/','/dev/shm/','/var/tmp/']):\n"
    "                    if '/lib' not in _LIB and '/usr' not in _LIB:\n"
    "                        __S__.stderr.write('error: library injection detected\\n'); __S__.exit(1)\n"
    "            for _LIB, _SEGS in _LIBS.items():\n"
    "                for _SS, _EE, _SP in _SEGS:\n"
    "                    if 'w' not in _SP: continue\n"
    "                    _SZ = min(_EE - _SS, 4096)\n"
    "                    if _SZ < 8: continue\n"
    "                    try:\n"
    "                        _ARR = (_CT.c_ubyte * _SZ)()\n"
    "                        _CT.memmove(_ARR, _SS, _SZ)\n"
    "                        for _OI in range(0, _SZ - 8, 8):\n"
    "                            _V = _ST.unpack('<Q', bytes(_ARR[_OI:_OI+8]))[0]\n"
    "                            if _V < 0x10000 or _V > 0x7FFFFFFFFFFF: continue\n"
    "                            _OK = False\n"
    "                            for _TSEGS in _LIBS.values():\n"
    "                                for _TS, _TE, _ in _TSEGS:\n"
    "                                    if _TS <= _V < _TE: _OK = True; break\n"
    "                                if _OK: break\n"
    "                            if not _OK:\n"
    "                                __S__.stderr.write('error: GOT hook detected\\n'); __S__.exit(1)\n"
    "                    except: pass\n"
    "        except: pass\n"
    "    elif __S__.platform == 'win32':\n"
    "        try:\n"
    "            import ctypes as _CT\n"
    "            _K32 = _CT.windll.kernel32\n"
    "            class _MBI(_CT.Structure):\n"
    "                _fields_ = [\n"
    "                    ('BaseAddress', _CT.c_void_p),\n"
    "                    ('AllocationBase', _CT.c_void_p),\n"
    "                    ('AllocationProtect', _CT.c_ulong),\n"
    "                    ('RegionSize', _CT.c_size_t),\n"
    "                    ('State', _CT.c_ulong),\n"
    "                    ('Protect', _CT.c_ulong),\n"
    "                    ('Type', _CT.c_ulong),\n"
    "                ]\n"
    "            _MODULES = ['kernel32.dll', 'ntdll.dll', 'user32.dll', 'ws2_32.dll']\n"
    "            for _MOD in _MODULES:\n"
    "                try:\n"
    "                    _HMOD = _K32.GetModuleHandleW(_MOD)\n"
    "                    if not _HMOD:\n"
    "                        continue\n"
    "                    _DOS = _CT.cast(_HMOD, _CT.POINTER(_CT.c_ubyte))\n"
    "                    _E_LFANEW = _CT.c_uint32.from_address(_CT.addressof(_DOS.contents) + 0x3C)\n"
    "                    _NTHDR = _CT.addressof(_DOS.contents) + _E_LFANEW.value\n"
    "                    _NSECT = _CT.c_uint16.from_address(_NTHDR + 6)\n"
    "                    _OPTSZ = _CT.c_uint16.from_address(_NTHDR + 4 + 16)\n"
    "                    _SECHDR = _NTHDR + 4 + 20 + _OPTSZ.value\n"
    "                    for _SI in range(_NSECT.value):\n"
    "                        _SEC = _SECHDR + _SI * 40\n"
    "                        _CHAR = _CT.c_uint32.from_address(_SEC + 36)\n"
    "                        if not (_CHAR.value & 0x80000000):\n"
    "                            continue\n"
    "                        _VADDR = _CT.c_uint32.from_address(_SEC + 12)\n"
    "                        _RSIZE = _CT.c_uint32.from_address(_SEC + 16)\n"
    "                        _SSIZE = min(_RSIZE.value, 4096)\n"
    "                        if _SSIZE < 8:\n"
    "                            continue\n"
    "                        _SDATA = (_CT.c_ubyte * _SSIZE)()\n"
    "                        _CT.memmove(_SDATA, _HMOD + _VADDR.value, _SSIZE)\n"
    "                        for _OI in range(0, _SSIZE - 8, 8):\n"
    "                            _PTR = _CT.c_void_p.from_address(_CT.addressof(_SDATA) + _OI)\n"
    "                            _VAL = _PTR.value\n"
    "                            if not _VAL or _VAL < 0x10000 or _VAL > 0x7FFFFFFF0000:\n"
    "                                continue\n"
    "                            _INFO = _MBI()\n"
    "                            _RET = _K32.VirtualQuery(_VAL, _CT.byref(_INFO), _CT.sizeof(_MBI))\n"
    "                            if _RET > 0 and _INFO.State == 0x1000:\n"
    "                                if _INFO.Protect == 0x40 and _INFO.Type == 0x20000:\n"
    "                                    __S__.stderr.write('error: IAT hook detected\\n'); __S__.exit(1)\n"
    "                except: pass\n"
    "        except: pass\n";

static const char ANTI_SYSCALL_HOOK_CODE_ARR[] =
    "    if __S__.platform == 'linux':\n"
    "        try:\n"
    "            import ctypes as _CT\n"
    "            _LIBC = _CT.CDLL('libc.so.6')\n"
    "            _CRIT_FUNCS = ['open', 'read', 'write', 'exit', 'close', 'mmap', 'mprotect']\n"
    "            for _FN in _CRIT_FUNCS:\n"
    "                try:\n"
    "                    _FADDR = getattr(_LIBC, _FN)\n"
    "                    _FB = bytes(_CT.c_ubyte.from_address(_FADDR + _I) for _I in range(12))\n"
    "                    if len(_FB) >= 10:\n"
    "                        if _FB[0] == 0x48 and _FB[1] == 0xB8 and _FB[10] == 0xFF and _FB[11] == 0xD0:\n"
    "                            __S__.stderr.write('error: syscall hook detected\\n'); __S__.exit(1)\n"
    "                except: pass\n"
    "        except: pass\n"
    "    elif __S__.platform == 'win32':\n"
    "        try:\n"
    "            import ctypes as _CT\n"
    "            _NTDLL = _CT.WinDLL('ntdll.dll')\n"
    "            for _FN in ('NtOpenProcess', 'NtReadVirtualMemory', 'NtWriteVirtualMemory',\n"
    "                        'NtCreateThreadEx', 'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',\n"
    "                        'NtClose', 'NtCreateFile', 'NtDeviceIoControlFile'):\n"
    "                try:\n"
    "                    _ADDR = getattr(_NTDLL, _FN)\n"
    "                    _PRO = bytes(_CT.c_ubyte.from_address(_ADDR + _I) for _I in range(12))\n"
    "                    if len(_PRO) >= 12:\n"
    "                        if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n"
    "                            __S__.stderr.write('error: ntdll syscall hook detected\\n'); __S__.exit(1)\n"
    "                        if _PRO[0] == 0xE9:\n"
    "                            __S__.stderr.write('error: ntdll detours hook detected\\n'); __S__.exit(1)\n"
    "                        if _PRO[0] == 0x68 and _PRO[5] == 0xC3:\n"
    "                            __S__.stderr.write('error: ntdll push-ret hook detected\\n'); __S__.exit(1)\n"
    "                except: pass\n"
    "        except: pass\n"
    "    elif __S__.platform == 'darwin':\n"
    "        try:\n"
    "            import ctypes as _CT\n"
    "            try:\n"
    "                _LIBC = _CT.CDLL('/usr/lib/libSystem.B.dylib')\n"
    "            except:\n"
    "                try:\n"
    "                    _LIBC = _CT.CDLL('/usr/lib/libSystem.dylib')\n"
    "                except:\n"
    "                    _LIBC = None\n"
    "            if _LIBC:\n"
    "                for _FN in ('open', 'read', 'write', 'exit', 'close', 'mmap', 'socket'):\n"
    "                    try:\n"
    "                        _ADDR = getattr(_LIBC, _FN)\n"
    "                        _PRO = bytes(_CT.c_ubyte.from_address(_ADDR + _I) for _I in range(12))\n"
    "                        if len(_PRO) >= 10:\n"
    "                            if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n"
    "                                __S__.stderr.write('error: syscall hook detected\\n'); __S__.exit(1)\n"
    "                    except: pass\n"
    "        except: pass\n";

static const char ANTI_MEM_INTEGRITY_CODE_ARR[] =
    "    if __S__.platform == 'linux':\n"
    "        try:\n"
    "            with open('/proc/self/maps') as _M:\n"
    "                _WX_COUNT = 0\n"
    "                _PRIVATE_EXEC = 0\n"
    "                for _L in _M:\n"
    "                    _P = _L.split()\n"
    "                    if len(_P) >= 2:\n"
    "                        if 'rwx' in _P[1]:\n"
    "                            _WX_COUNT += 1\n"
    "                            if '[heap]' in _L or '[anon' in _L:\n"
    "                                _PRIVATE_EXEC += 1\n"
    "                if _WX_COUNT > 10 or _PRIVATE_EXEC > 2:\n"
    "                    __S__.stderr.write('error: memory integrity check failed\\n'); __S__.exit(1)\n"
    "                for _L in _M:\n"
    "                    if '.so' in _L:\n"
    "                        _P = _L.split()\n"
    "                        if len(_P) >= 2 and 'r-xp' in _P[1]:\n"
    "                            _R = _P[0].split('-')\n"
    "                            if len(_R) == 2:\n"
    "                                try:\n"
    "                                    _S = int(_R[0], 16)\n"
    "                                    _E = int(_R[1], 16)\n"
    "                                    if _E - _S > 16*1024*1024:\n"
    "                                        __S__.stderr.write('error: large library mapping detected\\n'); __S__.exit(1)\n"
    "                                except: pass\n"
    "        except: pass\n"
    "    elif __S__.platform == 'win32':\n"
    "        try:\n"
    "            import ctypes as _CT\n"
    "            _K32 = _CT.windll.kernel32\n"
    "            class _MBI(_CT.Structure):\n"
    "                _fields_ = [\n"
    "                    ('BaseAddress', _CT.c_void_p),\n"
    "                    ('AllocationBase', _CT.c_void_p),\n"
    "                    ('AllocationProtect', _CT.c_ulong),\n"
    "                    ('RegionSize', _CT.c_size_t),\n"
    "                    ('State', _CT.c_ulong),\n"
    "                    ('Protect', _CT.c_ulong),\n"
    "                    ('Type', _CT.c_ulong),\n"
    "                ]\n"
    "            _MEM_COMMIT = 0x1000\n"
    "            _PAGE_RWX = 0x40\n"
    "            _MEM_PRIVATE = 0x20000\n"
    "            _ADDR = 0x10000\n"
    "            _WX_COUNT = 0\n"
    "            _PRIV_WX = 0\n"
    "            while _ADDR < 0x7FFFFFFF0000:\n"
    "                _INFO = _MBI()\n"
    "                _RET = _K32.VirtualQuery(_ADDR, _CT.byref(_INFO), _CT.sizeof(_MBI))\n"
    "                if _RET == 0:\n"
    "                    _ADDR += 0x10000\n"
    "                    continue\n"
    "                if _INFO.State == _MEM_COMMIT and _INFO.Protect == _PAGE_RWX:\n"
    "                    _WX_COUNT += 1\n"
    "                    if _INFO.Type == _MEM_PRIVATE:\n"
    "                        _PRIV_WX += 1\n"
    "                        if _INFO.RegionSize > 1048576:\n"
    "                            __S__.stderr.write('error: large private WX region detected\\n'); __S__.exit(1)\n"
    "                _ADDR += _INFO.RegionSize\n"
    "            if _PRIV_WX > 2 or _WX_COUNT > 10:\n"
    "                __S__.stderr.write('error: suspicious WX regions detected\\n'); __S__.exit(1)\n"
    "        except: pass\n"
    "    elif __S__.platform == 'darwin':\n"
    "        try:\n"
    "            import subprocess as _SP\n"
    "            try:\n"
    "                _VMLIST = _SP.check_output(['vmmap', '--pid', str(__S__.pid)], stderr=_SP.DEVNULL).decode('utf-8', errors='ignore')\n"
    "                _WX_LINES = [_L for _L in _VMLIST.split('\\n') if 'rwx' in _L.upper() or 'RWX' in _L]\n"
    "                _PRIV_WX = sum(1 for _L in _WX_LINES if '[anonymous' in _L or 'MALLOC' in _L or 'MACH_SECT' in _L)\n"
    "                if _PRIV_WX > 3 or len(_WX_LINES) > 15:\n"
    "                    __S__.stderr.write('error: suspicious WX regions detected\\n'); __S__.exit(1)\n"
    "            except: pass\n"
    "        except: pass\n";

const char *ANTI_DEBUG_CODE_PTR = ANTI_DEBUG_CODE_ARR;
const char *ANTI_FRIDA_CODE_PTR = ANTI_FRIDA_CODE_ARR;
const char *ANTI_HOOK_CODE_PTR = ANTI_HOOK_CODE_ARR;
const char *ANTI_INLINE_HOOK_CODE_PTR = ANTI_INLINE_HOOK_CODE_ARR;
const char *ANTI_PLT_HOOK_CODE_PTR = ANTI_PLT_HOOK_CODE_ARR;
const char *ANTI_SYSCALL_HOOK_CODE_PTR = ANTI_SYSCALL_HOOK_CODE_ARR;
const char *ANTI_MEM_INTEGRITY_CODE_PTR = ANTI_MEM_INTEGRITY_CODE_ARR;

// Generate salt-useable derived sub-keys from the user key
bool derive_sub_keys(const unsigned char *key, size_t key_len,
                             const unsigned char *salt, size_t salt_len,
                             unsigned char *out_layer1, size_t l1_sz,
                             unsigned char *out_layer2, size_t l2_sz,
                             unsigned char *out_layer3, size_t l3_sz) {
    // Derive 64 bytes of key material via PBKDF2
    unsigned char derived[64];
    if (PKCS5_PBKDF2_HMAC((const char *)key, (int)key_len,
                           salt, (int)salt_len,
                           5000, EVP_sha256(),
                           sizeof(derived), derived) != 1)
        return false;
    memcpy(out_layer1, derived, l1_sz);
    memcpy(out_layer2, derived + 16, l2_sz);
    memcpy(out_layer3, derived + 32, l3_sz);
    return true;
}

// Encode a key blob through 3 obfuscation layers (can be reversed in Python)
// Layers: rolling XOR → bit rotation + XOR → env-derived XOR
// NOTE: No PRNG-based permutation (avoids C rand() vs Python random mismatch)
std::string key_obfuscate_multi(std::string_view key,
                                        const unsigned char *salt,
                                        const unsigned char *layer1_key,
                                        const unsigned char *layer2_key,
                                        const unsigned char * /*layer3_key*/) {
    // Convert key to bytes for processing
    std::vector<unsigned char> key_bytes(key.begin(), key.end());
    size_t ksz = key_bytes.size();
    
    // Layer 2: Bit rotation + XOR (applied first, inner layer)
    // Uses layer1_key for both layers — Python stub only has _lk1 (= layer1_key)
    std::vector<unsigned char> rotated(ksz);
    for (size_t i = 0; i < ksz; i++) {
        unsigned char b = key_bytes[i];
        unsigned char shift = (layer1_key[8 + (i % 8)] & 7);  // use different bytes of same key
        b = (unsigned char)((b << shift) | (b >> (8 - shift)));
        b ^= layer1_key[i % 16];
        rotated[i] = b;
    }
    
    // Layer 1: Rolling XOR with state chaining (outer layer)
    std::vector<unsigned char> encrypted(ksz);
    unsigned char state = layer1_key[0];
    for (size_t i = 0; i < ksz; i++) {
        encrypted[i] = rotated[i] ^ state;
        state = (unsigned char)((encrypted[i] ^ layer1_key[(i + 1) % 16]) ^ 0x5A);
        state = (unsigned char)(((state << 3) & 0xFF) | (state >> 5));
    }
    
    // Encode as hex
    std::string out;
    out.reserve(ksz * 2);
    for (size_t i = 0; i < ksz; i++)
        out += std::format("{:02x}", encrypted[i]);
    return out;
}

// Build string pool: mix real key fragments with decoy entries
std::string build_string_pool(const std::string &key_hex,
                                      std::vector<int> &out_indices) {
    // Split key_hex into fragments of 4-8 chars
    std::vector<std::string> fragments;
    size_t pos = 0;
    int frag_id = 0;
    while (pos < key_hex.size()) {
        size_t frag_len = (rand() % 5) + 4; // 4-8 chars
        if (pos + frag_len > key_hex.size())
            frag_len = key_hex.size() - pos;
        fragments.push_back(key_hex.substr(pos, frag_len));
        out_indices.push_back(frag_id);
        frag_id++;
        pos += frag_len;
    }
    
    // Add 5-10 decoy fragments
    int num_decoys = 5 + (rand() % 6);
    static const char hex_chars[] = "0123456789abcdef";
    for (int d = 0; d < num_decoys; d++) {
        size_t dlen = (size_t)((rand() % 5) + 4);
        std::string decoy;
        for (size_t i = 0; i < dlen; i++)
            decoy += hex_chars[rand() % 16];
        // Insert decoy at random position among real fragments
        int insert_pos = rand() % ((int)fragments.size() + 1);
        fragments.insert(fragments.begin() + insert_pos, decoy);
        // Adjust indices: all indices >= insert_pos shift up
        for (auto &idx : out_indices) {
            if (idx >= insert_pos) idx++;
        }
    }
    
    // Build pool string: comma-separated fragments
    std::string pool;
    for (size_t i = 0; i < fragments.size(); i++) {
        if (i > 0) pool += ",";
        pool += std::format("\"{}\"", fragments[i]);
    }
    return pool;
}

// Generate a deterministic env-derived hash byte from env var name + xor_byte
// Uses ONLY the env var NAME (not value) so it's deterministic across all machines
unsigned char gen_env_hash_byte(int xor_byte) {
    const char *env_vars[] = {
        "HOME", "USER", "SHELL", "LANG", "TERM", "PATH", "PWD",
        "LOGNAME", "TZ", "LC_ALL", "EDITOR", "DISPLAY",
        "XDG_SESSION_ID", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"
    };
    int n_vars = sizeof(env_vars) / sizeof(env_vars[0]);
    int pick = rand() % n_vars;
    const char *name = env_vars[pick];
    unsigned int hash = 0;
    for (const char *p = name; *p; p++)
        hash = ((hash << 5) - hash) ^ (unsigned char)(*p);
    hash ^= (unsigned int)xor_byte;
    hash ^= (hash >> 16);
    return (unsigned char)(hash & 0xFF);
}

// Note: obfuscate_vm_key is done inline in protect_file() to avoid scope issues

// Legacy wrapper
std::string key_obfuscate(std::string_view key, int xor_byte) {
    std::string out;
    out.reserve(key.size() * 2);
    for (size_t i = 0; i < key.size(); i++)
        out += std::format("{:02x}", static_cast<unsigned char>(key[i] ^ xor_byte));
    return out;
}

int stub_algo_id(Algorithm algo) {
    switch (algo) {
        case ALGO_AES_ECB:  return 0;
        case ALGO_AES_CBC:  return 1;
        case ALGO_AES_CTR:  return 2;
        case ALGO_AES_GCM:  return 3;
        case ALGO_CHACHA20: return 4;
        case ALGO_CHACHA20_POLY1305: return 14;
        case ALGO_XCHACHA20_POLY1305: return 15;
        case ALGO_XOR:      return 5;
        case ALGO_ROLLING_XOR: return 11;
        case ALGO_MULTI_PASS_XOR: return 12;
        case ALGO_PRNG_XOR: return 13;
        case ALGO_BASE64:   return 6;
        case ALGO_BASE32:   return 7;
        case ALGO_BASE85:   return 8;
        case ALGO_ASCII85:  return 9;
        case ALGO_HEX:      return 10;
        default:            return -1;
    }
}

} /* namespace protect */
