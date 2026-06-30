#include "crypto/obfuscate.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>


char **anti_debug_sanitize_environment(void) {
    static const char *blocklist[] = {
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_OPENCL_LIBRARY_PATH",
        nullptr
    };
    extern char **environ;
    size_t count = 0;
    for (size_t i = 0; environ[i]; i++) count++;

    char **new_env = (char **)malloc((count + 1) * sizeof(char *));
    if (!new_env) return nullptr;

    size_t out = 0;
    for (size_t i = 0; environ[i]; i++) {
        int block = 0;
        for (int k = 0; blocklist[k]; k++) {
            size_t blen = strlen(blocklist[k]);
            if (strncmp(environ[i], blocklist[k], blen) == 0 &&
                environ[i][blen] == '=') {
                block = 1;
                break;
            }
        }
        if (!block) {
            new_env[out] = strdup(environ[i]);
            if (!new_env[out]) { /* cleanup on failure */ }
            out++;
        }
    }
    new_env[out] = nullptr;
    return new_env;
}


char *anti_debug_generate_stub(int include_vm_check, int include_hook_check) {
    std::string s;
    s.reserve(4096);

    s += "import sys as _SYS\n";
    s += "import os as _OS\n";
    s += "import platform as _PLATFORM\n";

    s += "_IS_WINDOWS = _PLATFORM.system() == 'Windows'\n";
    s += "_IS_MACOS = _PLATFORM.system() == 'Darwin'\n";
    s += "_IS_LINUX = _PLATFORM.system() == 'Linux'\n";
    
    s += "if _IS_WINDOWS:\n";
    s += "    try:\n";
    s += "        import ctypes as _CT\n";
    s += "        _K32 = _CT.windll.kernel32\n";
    s += "        if _K32.IsDebuggerPresent():\n";
    s += "            _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";
    
    s += "if _IS_LINUX:\n";
    s += "    try:\n";
    s += "        with open('/proc/self/status') as _F:\n";
    s += "            for _L in _F:\n";
    s += "                if 'TracerPid:' in _L:\n";
    s += "                    if _L.split(':')[1].strip() != '0':\n";
    s += "                        _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";
    
    s += "if _IS_MACOS:\n";
    s += "    try:\n";
    s += "        import ctypes as _CT\n";
    s += "        _LIBC = _CT.CDLL(None)\n";
    s += "        # sysctl CTL_KERN(1) KERN_PROC(14) KERN_PROC_PID(1) pid\n";
    s += "        _MIB = (_CT.c_int * 4)(1, 14, 1, _SYS.getpid())\n";
    s += "        _BUF = (_CT.c_char * 1024)()\n";
    s += "        _SIZE = _CT.c_size_t(1024)\n";
    s += "        if _LIBC.sysctl(_MIB, 4, _CT.byref(_BUF), _CT.byref(_SIZE), None, 0) == 0:\n";
    s += "            _RAW = bytes(_BUF)\n";
    s += "            P_TRACED = 0x800\n";
    s += "            # Check multiple possible p_flag offsets (macOS version-dependent)\n";
    s += "            for _OFF in (64, 68, 72, 76, 80):\n";
    s += "                if _OFF + 4 <= _SIZE.value:\n";
    s += "                    _FLAG = int.from_bytes(_RAW[_OFF:_OFF+4], 'little')\n";
    s += "                    if _FLAG & P_TRACED:\n";
    s += "                        _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";

    s += "try: _SYS.breakpointhook = None\n";
    s += "except: pass\n";

    s += "for _M in ('pydevd','pdb','ipdb','pdbpp','pydevconsole','trace'):\n";
    s += "    if _M in _SYS.modules:\n";
    s += "        _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";

    s += "if 'frida' in _SYS.modules:\n";
    s += "    _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "if _OS.environ.get('FRIDA_SCRIPT'):\n";
    s += "    _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "if _IS_LINUX or _IS_MACOS:\n";
    s += "    try:\n";
    s += "        import socket as _SK\n";
    s += "        _S = _SK.socket(_SK.AF_INET, _SK.SOCK_STREAM)\n";
    s += "        _S.settimeout(1.0)\n";
    s += "        if _S.connect_ex(('127.0.0.1', 27042)) == 0:\n";
    s += "            _S.close()\n";
    s += "            _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "        _S.close()\n";
    s += "    except: pass\n";
    s += "if _IS_LINUX:\n";
    s += "    try:\n";
    s += "        with open('/proc/self/maps') as _F:\n";
    s += "            if 'frida' in _F.read():\n";
    s += "                _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";
    s += "    try:\n";
    s += "        with open('/proc/self/cmdline') as _F:\n";
    s += "            _C = _F.read()\n";
    s += "        with open('/proc/self/status') as _F:\n";
    s += "            for _L in _F:\n";
    s += "                if 'frida' in _L.lower():\n";
    s += "                    _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";
    s += "if _IS_MACOS:\n";
    s += "    try:\n";
    s += "        import subprocess as _SP\n";
    s += "        if 'frida' in _SP.check_output(['ps', 'aux'], stderr=_SP.DEVNULL).decode().lower():\n";
    s += "            _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";
    s += "    for _P in _OS.listdir('/tmp'):\n";
    s += "        if 'frida' in _P.lower():\n";
    s += "            _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "            break\n";

    if (include_hook_check) {
        s += "_B = _SYS.modules.get('builtins')\n";
        s += "_HOOKED = 0\n";
        s += "for _N in ('__import__','compile','exec','eval','open'):\n";
        s += "    _F = getattr(_B, _N, None)\n";
        s += "    if _F is None:\n";
        s += "        _HOOKED = 1; break\n";
        s += "    _G = getattr(_F, '__name__', '')\n";
        s += "    if _G != _N:\n";
        s += "        _HOOKED = 1; break\n";
        s += "if _HOOKED:\n";
        s += "    _SYS.stderr.write('error: hook detected\\n'); _SYS.exit(1)\n";
        
        s += "_BT = type(getattr(_B, '__build_class__', None))\n";
        s += "if _BT.__name__ != 'builtin_function_or_method':\n";
        s += "    _SYS.stderr.write('error: builtin tampering detected\\n'); _SYS.exit(1)\n";
        
        s += "_ST = type(getattr(_SYS, 'settrace', None))\n";
        s += "if _ST.__name__ != 'builtin_function_or_method':\n";
        s += "    _SYS.stderr.write('error: sys tampering detected\\n'); _SYS.exit(1)\n";
        
        s += "for _EV in ('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT','LD_DEBUG',\n";
        s += "            'LD_OPENCL_LIBRARY_PATH','DYLD_INSERT_LIBRARIES',\n";
        s += "            'DYLD_LIBRARY_PATH','DYLD_FORCE_FLAT_NAMESPACE'):\n";
        s += "    if _OS.environ.get(_EV):\n";
        s += "        _SYS.stderr.write('error: injection detected\\n'); _SYS.exit(1)\n";
        
        s += "if _IS_LINUX:\n";
        s += "    try:\n";
        s += "        with open('/proc/self/maps') as _M:\n";
        s += "            for _L in _M:\n";
        s += "                if 'rwx' in _L and '[' not in _L:\n";
        s += "                    _SYS.stderr.write('error: WX memory detected\\n'); _SYS.exit(1)\n";
        s += "                if any(x in _L for x in ('/tmp/','/dev/shm/','hook','intercept')):\n";
        s += "                    _SYS.stderr.write('error: hook injection detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";
        
        s += "_TR = _SYS.gettrace()\n";
        s += "if _TR is not None:\n";
        s += "    _SYS.stderr.write('error: tracer detected\\n'); _SYS.exit(1)\n";
        
        s += "if _IS_WINDOWS:\n";
        s += "    try:\n";
        s += "        import winreg as _WR\n";
        s += "        try:\n";
        s += "            _K = _WR.OpenKey(_WR.HKEY_LOCAL_MACHINE,\n";
        s += "                r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows')\n";
        s += "            _V, _ = _WR.QueryValueEx(_K, 'AppInit_DLLs')\n";
        s += "            _WR.CloseKey(_K)\n";
        s += "            if _V:\n";
        s += "                _SYS.stderr.write('error: DLL injection detected\\n'); _SYS.exit(1)\n";
        s += "        except: pass\n";
        s += "    except: pass\n";
        
        s += "if _IS_MACOS:\n";
        s += "    for _DY in ('DYLD_INSERT_LIBRARIES','DYLD_LIBRARY_PATH',\n";
        s += "                'DYLD_FORCE_FLAT_NAMESPACE'):\n";
        s += "        if _OS.environ.get(_DY):\n";
        s += "            _SYS.stderr.write('error: DYLD injection detected\\n'); _SYS.exit(1)\n";

        s += "if _IS_LINUX:\n";
        s += "    try:\n";
        s += "        _WX_COUNT = 0\n";
        s += "        _PRIVATE_WX = 0\n";
        s += "        with open('/proc/self/maps') as _M:\n";
        s += "            for _L in _M:\n";
        s += "                if ' rwx' in _L:\n";
        s += "                    _WX_COUNT += 1\n";
        s += "                    if '[heap]' in _L or '[anon' in _L:\n";
        s += "                        _PRIVATE_WX += 1\n";
        s += "        if _WX_COUNT > 10 or _PRIVATE_WX > 2:\n";
        s += "            _SYS.stderr.write('error: suspicious memory regions detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";

        s += "if _IS_LINUX:\n";
        s += "    try:\n";
        s += "        import ctypes as _CT\n";
        s += "        _LIBC = _CT.CDLL('libc.so.6')\n";
        s += "        for _FN in ('open', 'read', 'write', 'execve', 'system'):\n";
        s += "            try:\n";
        s += "                _ADDR = getattr(_LIBC, _FN)\n";
        s += "                _PROLOGUE = b''\n";
        s += "                for _I in range(16):\n";
        s += "                    try:\n";
        s += "                        _PROLOGUE += _CT.c_ubyte.from_address(_ADDR + _I)\n";
        s += "                    except: break\n";
        s += "                if len(_PROLOGUE) >= 8:\n";
        s += "                    if _PROLOGUE[0] == 0x48 and _PROLOGUE[1] == 0xB8 and _PROLOGUE[10] == 0xFF and _PROLOGUE[11] == 0xD0:\n";
        s += "                        _SYS.stderr.write('error: inline hook detected\\n'); _SYS.exit(1)\n";
        s += "            except: pass\n";
        s += "    except: pass\n";

        s += "if _IS_WINDOWS:\n";
        s += "    try:\n";
        s += "        import ctypes as _CT\n";
        s += "        _K32 = _CT.windll.kernel32\n";
        s += "        _NTDLL = _CT.WinDLL('ntdll.dll')\n";
        s += "        for _FN in ('OpenProcess', 'ReadProcessMemory', 'WriteProcessMemory',\n";
        s += "                    'CreateRemoteThread', 'VirtualProtectEx'):\n";
        s += "            try:\n";
        s += "                _ADDR = getattr(_K32, _FN)\n";
        s += "                _PRO = b''\n";
        s += "                for _I in range(12):\n";
        s += "                    try:\n";
        s += "                        _PRO += _CT.c_ubyte.from_address(_ADDR + _I)\n";
        s += "                    except: break\n";
        s += "                if len(_PRO) >= 8:\n";
        s += "                    if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n";
        s += "                        _SYS.stderr.write('error: inline hook detected\\n'); _SYS.exit(1)\n";
        s += "                    if _PRO[0] == 0xE9:\n";
        s += "                        _SYS.stderr.write('error: detours hook detected\\n'); _SYS.exit(1)\n";
        s += "                    if _PRO[0] == 0x68 and _PRO[5] == 0xC3:\n";
        s += "                        _SYS.stderr.write('error: push-ret hook detected\\n'); _SYS.exit(1)\n";
        s += "            except: pass\n";
        s += "        for _FN in ('NtOpenProcess', 'NtReadVirtualMemory', 'NtWriteVirtualMemory',\n";
        s += "                    'NtCreateThreadEx', 'NtProtectVirtualMemory'):\n";
        s += "            try:\n";
        s += "                _ADDR = getattr(_NTDLL, _FN)\n";
        s += "                _PRO = b''\n";
        s += "                for _I in range(12):\n";
        s += "                    try:\n";
        s += "                        _PRO += _CT.c_ubyte.from_address(_ADDR + _I)\n";
        s += "                    except: break\n";
        s += "                if len(_PRO) >= 8:\n";
        s += "                    if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n";
        s += "                        _SYS.stderr.write('error: ntdll hook detected\\n'); _SYS.exit(1)\n";
        s += "                    if _PRO[0] == 0xE9:\n";
        s += "                        _SYS.stderr.write('error: ntdll detours hook detected\\n'); _SYS.exit(1)\n";
        s += "            except: pass\n";
        s += "    except: pass\n";

        s += "if _IS_LINUX:\n";
        s += "    try:\n";
        s += "        import ctypes as _CT\n";
        s += "        _LIBC = _CT.CDLL('libc.so.6')\n";
        s += "        _SYSCALLS = ['open', 'read', 'write', 'exit', 'close', 'mmap']\n";
        s += "        for _S in _SYSCALLS:\n";
        s += "            try:\n";
        s += "                _SADDR = getattr(_LIBC, _S)\n";
        s += "                _SB = b''\n";
        s += "                for _J in range(12):\n";
        s += "                    try: _SB += _CT.c_ubyte.from_address(_SADDR + _J)\n";
        s += "                    except: break\n";
        s += "                if _SB[:3] == b'\\x48\\xb8' and _SB[10:12] == b'\\xff\\xd0':\n";
        s += "                    _SYS.stderr.write('error: syscall hook detected\\n'); _SYS.exit(1)\n";
        s += "            except: pass\n";
        s += "    except: pass\n";
        s += "if _IS_WINDOWS:\n";
        s += "    try:\n";
        s += "        import ctypes as _CT\n";
        s += "        _NTDLL = _CT.WinDLL('ntdll.dll')\n";
        s += "        for _FN in ('NtOpenProcess', 'NtReadVirtualMemory', 'NtWriteVirtualMemory',\n";
        s += "                    'NtCreateThreadEx', 'NtAllocateVirtualMemory'):\n";
        s += "            try:\n";
        s += "                _ADDR = getattr(_NTDLL, _FN)\n";
        s += "                _PRO = b''\n";
        s += "                for _I in range(12):\n";
        s += "                    try:\n";
        s += "                        _PRO += _CT.c_ubyte.from_address(_ADDR + _I)\n";
        s += "                    except: break\n";
        s += "                if len(_PRO) >= 8:\n";
        s += "                    if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n";
        s += "                        _SYS.stderr.write('error: ntdll syscall hook detected\\n'); _SYS.exit(1)\n";
        s += "                    if _PRO[0] == 0xE9:\n";
        s += "                        _SYS.stderr.write('error: ntdll detours hook detected\\n'); _SYS.exit(1)\n";
        s += "            except: pass\n";
        s += "    except: pass\n";
        s += "if _IS_LINUX:\n";
        s += "    try:\n";
        s += "        _WX_COUNT = 0\n";
        s += "        with open('/proc/self/maps') as _M:\n";
        s += "            for _L in _M:\n";
        s += "                if ' rwx' in _L:\n";
        s += "                    _WX_COUNT += 1\n";
        s += "        if _WX_COUNT > 10:\n";
        s += "            _SYS.stderr.write('error: suspicious WX regions detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";
        s += "if _IS_WINDOWS:\n";
        s += "    try:\n";
        s += "        import ctypes as _CT\n";
        s += "        _K32 = _CT.windll.kernel32\n";
        s += "        class _MEMORY_BASIC_INFORMATION(_CT.Structure):\n";
        s += "            _fields_ = [\n";
        s += "                ('BaseAddress', _CT.c_void_p),\n";
        s += "                ('AllocationBase', _CT.c_void_p),\n";
        s += "                ('AllocationProtect', _CT.c_ulong),\n";
        s += "                ('RegionSize', _CT.c_size_t),\n";
        s += "                ('State', _CT.c_ulong),\n";
        s += "                ('Protect', _CT.c_ulong),\n";
        s += "                ('Type', _CT.c_ulong),\n";
        s += "            ]\n";
        s += "        _MEM_COMMIT = 0x1000\n";
        s += "        _PAGE_EXECUTE_READWRITE = 0x40\n";
        s += "        _MEM_PRIVATE = 0x20000\n";
        s += "        _SI = _CT.c_void_p(0)\n";
        s += "        _ADDR = 0x10000\n";
        s += "        _WX_COUNT = 0\n";
        s += "        _PRIV_WX = 0\n";
        s += "        while _ADDR < 0x7FFFFFFF0000:\n";
        s += "            _MBI = _MEMORY_BASIC_INFORMATION()\n";
        s += "            _RET = _K32.VirtualQuery(_ADDR, _CT.byref(_MBI), _CT.sizeof(_MBI))\n";
        s += "            if _RET == 0:\n";
        s += "                _ADDR += 0x10000\n";
        s += "                continue\n";
        s += "            if _MBI.State == _MEM_COMMIT and _MBI.Protect == _PAGE_EXECUTE_READWRITE:\n";
        s += "                _WX_COUNT += 1\n";
        s += "                if _MBI.Type == _MEM_PRIVATE:\n";
        s += "                    _PRIV_WX += 1\n";
        s += "                    if _MBI.RegionSize > 1048576:\n";
        s += "                        _SYS.stderr.write('error: large private WX region detected\\n'); _SYS.exit(1)\n";
        s += "            _ADDR += _MBI.RegionSize\n";
        s += "        if _PRIV_WX > 2 or _WX_COUNT > 10:\n";
        s += "            _SYS.stderr.write('error: suspicious memory regions detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";
    }

    s += "if len(_SYS.meta_path) > 5:\n";
    s += "    _SYS.stderr.write('error: import hook detected\\n'); _SYS.exit(1)\n";

    s += "try:\n";
    s += "    import time as _T\n";
    s += "    _T1 = _T.perf_counter()\n";
    s += "    _ = [i for i in range(1000)]\n";
    s += "    _T2 = _T.perf_counter()\n";
    s += "    if _T2 - _T1 > 5.0:\n";
    s += "        _SYS.stderr.write('error: slowdown detected\\n'); _SYS.exit(1)\n";
    s += "except: pass\n";

    s += "try:\n";
    s += "    _G = _SYS._getframe\n";
    s += "    _FD = 0\n";
    s += "    _F = _G()\n";
    s += "    while _F:\n";
    s += "        _FD += 1\n";
    s += "        if _FD > 50:\n";
    s += "            _SYS.stderr.write('error: deep frame inspection detected\\n'); _SYS.exit(1)\n";
    s += "        _F = _F.f_back\n";
    s += "except: pass\n";

    s += "_SYS.settrace(None)\n";
    s += "_SYS.setprofile(None)\n";

    s += "try:\n";
    s += "    _EH = type(getattr(_SYS, 'excepthook', None))\n";
    s += "    if _EH.__name__ != 'builtin_function_or_method':\n";
    s += "        _SYS.stderr.write('error: exception hook tampered\\n'); _SYS.exit(1)\n";
    s += "    _UH = type(getattr(_SYS, 'unraisablehook', None))\n";
    s += "    if _UH.__name__ != 'builtin_function_or_method':\n";
    s += "        _SYS.stderr.write('error: unraisable hook tampered\\n'); _SYS.exit(1)\n";
    s += "except: pass\n";

    s += "try:\n";
    s += "    _AH = _SYS.getaudithook()\n";
    s += "    if _AH is not None:\n";
    s += "        _SYS.stderr.write('error: audit hook detected\\n'); _SYS.exit(1)\n";
    s += "except: pass\n";

    s += "try:\n";
    s += "    import gc as _GC\n";
    s += "    for _O in _GC.get_objects():\n";
    s += "        _TN = type(_O).__name__\n";
    s += "        if _TN in ('PyDevdFrame','Debugger','Tracer','Profiler'):\n";
    s += "            _SYS.stderr.write('error: debugger object detected\\n'); _SYS.exit(1)\n";
    s += "except: pass\n";

    s += "try:\n";
    s += "    import inspect as _INS\n";
    s += "except: pass\n";

    s += "try:\n";
    s += "    import socket as _SK\n";
    s += "    _S2 = _SK.socket(_SK.AF_INET, _SK.SOCK_STREAM)\n";
    s += "    _S2.settimeout(1.0)\n";
    s += "    if _S2.connect_ex(('127.0.0.1', 5678)) == 0:\n";
    s += "        _S2.close()\n";
    s += "        _SYS.stderr.write('error: debugger port detected\\n'); _SYS.exit(1)\n";
    s += "    _S2.close()\n";
    s += "except: pass\n";

    if (include_vm_check) {
        s += "if getattr(_SYS, 'flags', None) and _SYS.flags.no_user_site:\n";
        s += "    _SYS.stderr.write('error: sandbox detected\\n'); _SYS.exit(1)\n";
        
        s += "if _IS_MACOS:\n";
        s += "    if any(x in str(_PLATFORM.platform()) for x in ['vmware','virtualbox','qemu','parallels']):\n";
        s += "        _SYS.stderr.write('error: VM detected\\n'); _SYS.exit(1)\n";
        
        s += "if _IS_LINUX:\n";
        s += "    if any(x in str(_PLATFORM.platform()) for x in ['vmware','virtualbox','qemu']):\n";
        s += "        _SYS.stderr.write('error: VM detected\\n'); _SYS.exit(1)\n";
        s += "    try:\n";
        s += "        with open('/proc/1/cgroup') as _F:\n";
        s += "            if any('docker' in _L or 'kubepods' in _L for _L in _F):\n";
        s += "                _SYS.stderr.write('error: container detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";
        s += "    if _OS.path.exists('/.dockerenv'):\n";
        s += "        _SYS.stderr.write('error: container detected\\n'); _SYS.exit(1)\n";
        
        s += "if _IS_WINDOWS:\n";
        s += "    try:\n";
        s += "        if _OS.path.exists('C:\\\\windows\\\\system32\\\\wine'):\n";
        s += "            _SYS.stderr.write('error: Wine detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";
        s += "    if _PLATFORM.system() == 'Windows' and _OS.environ.get('WINELOADER'):\n";
        s += "        _SYS.stderr.write('error: Wine detected\\n'); _SYS.exit(1)\n";
    }

    return strdup(s.c_str());
}
