# VM Architecture Enhancement Specification
## Advanced Obfuscation & Anti-Reverse Engineering Extensions

---

## 1. Variable-Length Instruction Encoding

### 1.1 Design Rationale

Current fixed-size 8-byte encoding (`VM_INSTR_SIZE = 8`) enables straightforward instruction-level alignment analysis. An adversary can trivially partition the bytecode stream at 8-byte boundaries and analyze each slot independently. Variable-length encoding destroys this alignment guarantee, forcing the analyst to implement a full variable-length decoder before any semantic analysis can begin.

### 1.2 Encoding Format

Each instruction begins with a **tag byte** whose upper 2 bits encode the length class:

| Tag Bits (b7:b6) | Length Class | Total Size  | Description                    |
|------------------|-------------|-------------|--------------------------------|
| `00`             | Short       | 2 bytes     | Register-only (no imm)         |
| `01`             | Medium      | 4 bytes     | Register + short imm (16-bit)  |
| `10`             | Long        | 8+ bytes    | Full format (legacy compat)    |
| `11`             | Extended    | Variable    | Multi-word (indirect, vtable)  |

**Tag byte layout:**

```
Short (2B):     [TT00_OOOO] [RD3_RD2_RD1_RD0_RS_RS_RS_RS]
                TT=00, OOOO=4-bit opcode, RD=4-bit dest, RS=4-bit src

Medium (4B):    [TT01_OOOO] [RD_RD_RD_RD_RS_RS_RS_RS] [IMM_LOW8] [IMM_HIGH8]
                TT=01, OOOOO=5-bit opcode, RD=4-bit, RS=4-bit, IMM=16-bit

Long (8B):      [TT10_OOOO] [OPCODE(8)] [RD(8)] [RS1(8)] [RS2(8)] [IMM(32)]
                TT=10, full legacy-compatible 8-byte format, 8-bit opcode

Extended (var): [TT11_LLLL] [EXT_OP(8)] [PAYLOAD(VAR)]
                TT=11, LLLL=4-bit length multiplier (×8 bytes), 
                EXT_OP=extended opcode byte, PAYLOAD = LLLL×8 - 2 bytes
```

### 1.3 Opcode Mapping Integration

The random opcode shuffle already applied at compile time (in `vm_compile.cpp`) operates on the **canonical opcode value** before encoding. With variable-length encoding:

1. The compile pipeline assigns canonical opcodes from the existing `VmOpcode` enum.
2. The forward shuffle map transforms canonical → shuffled opcode.
3. The **encoder** selects the appropriate length class based on operand requirements:
   - `rd, rs1` only → Short (2B) if opcode fits in 4 bits
   - `rd, rs, imm16` → Medium (4B)
   - `rd, rs1, rs2, imm32` → Long (8B)
   - Complex (indirect/vtable/exception) → Extended (var)
4. The shuffled opcode is placed into the variable-length frame's opcode field.
5. The inverse map (stored in `opcode_map[256]`) remains unchanged—the interpreter decodes variable-length frames, extracts the shuffled opcode byte, and applies the inverse map as before.

```python
# Encoding selection pseudocode
def encode_instruction(canonical_op, rd, rs1, rs2, imm):
    shuffled_op = forward_map[canonical_op]
    
    # Classify
    if rs2 == 0 and imm == 0 and fits_in_4bit(canonical_op):
        # Short form: 2 bytes
        tag = 0x00  # TT=00
        return bytes([tag | (shuffled_op & 0x0F), 
                      (rd << 4) | (rs1 & 0x0F)])
    
    elif rs2 == 0 and fits_in_16bit(imm) and fits_in_5bit(canonical_op):
        # Medium form: 4 bytes
        tag = 0x40  # TT=01
        imm16 = imm & 0xFFFF
        return bytes([tag | (shuffled_op & 0x1F),
                      (rd << 4) | (rs1 & 0x0F),
                      imm16 & 0xFF,
                      (imm16 >> 8) & 0xFF])
    
    elif is_extended_instruction(canonical_op):
        # Extended form: variable length
        payload = encode_extended_payload(canonical_op, rd, rs1, rs2, imm)
        num_blocks = (len(payload) + 6) // 8  # round up to 8-byte blocks
        tag = 0xC0 | (num_blocks & 0x0F)  # TT=11
        return bytes([tag, shuffled_op]) + payload
    
    else:
        # Long form: 8 bytes (legacy)
        tag = 0x80  # TT=10
        return struct.pack('<BBBBi', tag | 0x00, shuffled_op, rd, rs1, rs2, imm)
```

### 1.4 Decoding in Interpreter

The Python interpreter (`vm_interp_py.h`) gains a variable-length decoder:

```python
def _decode_vl(_code, _ip):
    _tag = _code[_ip]
    _len_class = (_tag >> 6) & 0x03
    
    if _len_class == 0:  # Short: 2 bytes
        _op_shuf = _code[_ip] & 0x0F
        _rd = (_code[_ip+1] >> 4) & 0x0F
        _rs1 = _code[_ip+1] & 0x0F
        _rs2 = 0
        _imm = 0
        _size = 2
        
    elif _len_class == 1:  # Medium: 4 bytes
        _op_shuf = _code[_ip] & 0x1F
        _rd = (_code[_ip+1] >> 4) & 0x0F
        _rs1 = _code[_ip+1] & 0x0F
        _rs2 = 0
        _imm = _code[_ip+2] | (_code[_ip+3] << 8)
        _size = 4
        
    elif _len_class == 2:  # Long: 8 bytes (legacy)
        _op_shuf = _code[_ip+1]
        _rd = _code[_ip+2]
        _rs1 = _code[_ip+3]
        _rs2 = _code[_ip+4]
        _imm = (_code[_ip+5] | (_code[_ip+6] << 8) | 
                (_code[_ip+7] << 16) | (_code[_ip+8] << 24))
        _size = 8
        
    else:  # Extended: variable (TT=11)
        _num_blocks = _code[_ip] & 0x0F
        _op_shuf = _code[_ip+1]
        _payload = _code[_ip+2 : _ip+2 + _num_blocks*8 - 2]
        _size = 2 + _num_blocks * 8
        # Decode extended payload...
        
    _op = _map[_op_shuf]  # Apply inverse opcode map
    return _op, _rd, _rs1, _rs2, _imm, _size
```

### 1.5 Security Analysis

- **Pattern matching resistance**: Fixed 8-byte patterns no longer exist. Signature-based detection of specific instruction sequences becomes infeasible.
- **Disassembly complexity**: Any static analysis tool must implement the full variable-length decoder, including the extended format, before it can begin CFG reconstruction.
- **Entropy distribution**: The tag byte's upper bits introduce structural variation that defeats simple statistical analysis.
- **Compatibility**: Long form (8B) preserves backward compatibility with existing instruction sequences, allowing incremental adoption.

---

## 2. ISA Design Expansion

### 2.1 New Opcode Definitions

Add to the `VmOpcode` enum in `vm.h`:

```c
typedef enum {
    // ...existing opcodes (0-75)...
    
    // Indirect & Virtual Call (80-89)
    VM_CALL_INDIRECT = 80,  // call through register pointer
    VM_CALL_VTABLE   = 81,  // virtual method dispatch (vtable-like)
    
    // Exception Handling (90-99)
    VM_TRY           = 90,  // begin try block
    VM_CATCH         = 91,  // define catch handler
    VM_THROW         = 92,  // raise exception
    VM_END_TRY       = 93,  // end try block
    VM_EXCEPTION_TYPE = 94, // get exception type into register
    
    // Extended Conditional Branching (100-115)
    VM_JMP_IF_TRUE   = 100, // jump if rd is truthy (enhanced)
    VM_JMP_IF_FALSE  = 101, // jump if rd is falsy (enhanced)
    VM_JMP_EQ        = 102, // jump if rd == rs1
    VM_JMP_NE        = 103, // jump if rd != rs1
    VM_JMP_LT        = 104, // jump if rd < rs1
    VM_JMP_LE        = 105, // jump if rd <= rs1
    VM_JMP_GT        = 106, // jump if rd > rs1
    VM_JMP_GE        = 107, // jump if rd >= rs1
    VM_JMP_INDIRECT  = 108, // jump through register (indirect)
    VM_JMP_TABLE     = 109, // jump through offset table (switch)
    
    // Register Spilling (120-129)
    VM_SPILL         = 120, // spill register to VM stack
    VM_RESTORE       = 121, // restore register from VM stack
    VM_SPILL_MANY    = 122, // spill multiple registers
    VM_RESTORE_MANY  = 123, // restore multiple registers
    
    // Self-Modifying Code (130-139)
    VM_PATCH_INSTR   = 130, // patch an instruction at runtime
    VM_PATCH_OPCODE  = 131, // patch opcode map entry
    VM_ENCRYPT_SEG   = 132, // XOR-encrypt code segment
    VM_DECRYPT_SEG   = 133, // XOR-decrypt code segment
    
    // Data Obfuscation (140-149)
    VM_OBF_MOVE      = 140, // obfuscated register move (opaque expression)
    VM_OBF_ADD       = 141, // obfuscated addition
    VM_OBF_XOR       = 142, // obfuscated XOR via arithmetic
    
} VmOpcode;
```

### 2.2 Indirect Call: `VM_CALL_INDIRECT`

**Semantics**: Call a function whose reference is stored in a register. This is equivalent to calling through a function pointer in C/C++.

```
Encoding: Extended (variable length)
Format:   [TAG=0xC2] [OP=80] [RD(1)] [RS1(1)] [ARG_COUNT(2)] [PADDING(2)]

Semantics:
  _fn_val = _r[rs1]
  if not callable(_fn_val): raise VM_EXCEPTION("indirect call failed")
  
  # Extract args from consecutive registers starting at rs1+1
  _args = [_r[rs1 + 1 + i] for i in range(arg_count)]
  
  _result = _fn_val(*_args)
  _r[rd] = _result
```

**Interpreter implementation** (Python):
```python
elif _op == 80:  # VM_CALL_INDIRECT
    _fn = _r[_rs1]
    _argc = _imm & 0xFFFF
    _args = tuple(_r[_rs1 + 1 + _i] for _i in range(_argc))
    _r[_rd] = _fn(*_args)
```

**Obfuscation benefit**: Indirect calls break the call graph that static analysis can reconstruct. The target function is only resolved at runtime, defeating call-target analysis.

### 2.3 Virtual Call: `VM_CALL_VTABLE`

**Semantics**: Simulate C++ vtable dispatch. An object register holds a dispatch table (dictionary or list of methods). The method index selects which method to call.

```
Encoding: Extended (variable length)
Format:   [TAG=0xC3] [OP=81] [RD(1)] [RS1(obj)(1)] [VTBL_IDX(2)] [ARG_COUNT(2)] [PADDING(2)]

Semantics:
  _obj = _r[rs1]
  _vtable = _r[rs1 + 1]       # vtable register (next to obj)
  _method = _vtable[vtbl_idx]  # dispatch by index
  _args = tuple(_r[rs1 + 2 + i] for i in range(arg_count))
  _r[rd] = _method(_obj, *_args)  # pass self/obj as first arg
```

**Obfuscation benefit**: Vtable dispatch mirrors C++ virtual calls. An adversary tracking concrete types through the VM must implement full type inference. Since the vtable is stored in a runtime register and the dispatch index is computed, static reconstruction of call targets requires solving for the runtime value of the vtable register.

**Compiler integration** (compile-time vtable construction):
```python
# In vm_compile.cpp / vm_py.h compilation pass:
# Detect patterns of: obj.method(args) → synthesize VM_CALL_VTABLE

def emit_virtual_call(obj_reg, method_name, arg_regs, rd):
    # Build vtable in constant pool
    vtable_idx = const_pool.add(method_name)
    
    # Load vtable object (if not already loaded)
    if not vtable_loaded[obj_reg]:
        emit(VM_LOAD_ATTR, vtbl_reg, obj_reg, "__methods__")
        vtable_loaded[obj_reg] = vtbl_reg
    
    # Arrange args consecutively
    for i, a in enumerate(arg_regs):
        if a != obj_reg + 2 + i:
            emit(VM_MOVE, obj_reg + 2 + i, a)
    
    # Emit virtual call
    emit_extended(VM_CALL_VTABLE, rd, obj_reg, 
                  (vtable_idx << 16) | len(arg_regs))
```

### 2.4 Exception Handling: `VM_TRY`, `VM_CATCH`, `VM_THROW`, `VM_END_TRY`

**Semantics**: Structured exception handling within the VM, analogous to C++ try/catch.

**State**: The VM maintains an **exception handler stack** — a list of `(try_start_ip, try_end_ip, catch_ip, exception_type)` tuples.

```
VM_TRY:    Begin a try block
  Encoding: Long (8B)
  Format:   [TAG=0x8A] [OP=90] [RD(0)] [RS1(0)] [RS2(0)] [HANDLER_OFFSET(4)]
  
  Semantics:
    _handler_stack.append({
        'try_start': _ip,
        'try_end': _ip + handler_offset,  # computed at decode
        'catch_ip': _ip + handler_offset,
        'type_filter': None
    })

VM_CATCH:  Define catch handler for specific exception type
  Encoding: Extended
  Format:   [TAG=0xCB] [OP=91] [RD(1)] [RS1(0)] [TYPE_REG(1)] [RESERVED(2)] [PADDING(2)]
  
  Semantics:
    _handler_stack[-1]['catch_type'] = _r[type_reg]
    _handler_stack[-1]['catch_ip'] = _ip + 1  # next instruction

VM_THROW:  Raise an exception
  Encoding: Medium (4B)
  Format:   [TAG=0x5C] [OP=92] [RD(1)] [RS1(exc_reg)(4)] [EXC_IMM(16)]
  
  Semantics:
    _exc_val = _r[exc_reg]
    _exc_type = type(_exc_val)
    
    # Walk handler stack from top
    _found = False
    for _h in reversed(_handler_stack):
        if _h['try_start'] <= _ip <= _h['try_end']:
            if (_h['catch_type'] is None or 
                isinstance(_exc_val, _h['catch_type']) or
                type(_exc_val) == _h['catch_type']):
                # Unwind registers, jump to handler
                _unwind_regs_to_snapshot()
                _ip = _h['catch_ip']
                _r[_exc_reg] = _exc_val  # exception object in reg
                _found = True
                break
    if not _found:
        # Re-raise to host (Python)
        raise _exc_val

VM_END_TRY: End try block, pop handler
  Encoding: Short (2B)
  Format:   [TAG=0x0D] [OPCODE(4)=0x0D] [RSVD(4)] [RSVD(8)]
  
  Semantics:
    if _handler_stack:
        _handler_stack.pop()
```

**Custom exception types** are supported via the constant pool. Exception type objects can be:
- Python exception classes (from `__builtins__`)
- Custom exception classes defined in the VM-executed code
- Strings used as exception type discriminators

**Integration with existing code**: The `FOR_ITER` instruction already uses a try/except internally (for `StopIteration`). The new exception mechanism extends this to arbitrary user code.

**Anti-analysis benefit**: Exception handling introduces implicit control flow edges that are invisible to static analysis. A `VM_THROW` can transfer control to a `VM_CATCH` handler at an unpredictable location, creating control flow that can only be resolved by analyzing runtime exception propagation.

---

## 3. Control Flow Obfuscation

### 3.1 Obfuscated Conditional Branching

The existing `VM_JMP_IF_TRUE` (31) and `VM_JMP_IF_FALSE` (32) test register values directly. The enhanced versions obfuscate the condition evaluation using **boolean expression decomposition** and **arithmetic transforms**.

#### 3.1.1 Boolean Expression Decomposition

Instead of a single condition test, decompose into an algebraically equivalent expression:

```
Standard:     if _r[rd]: jump target
Obfuscated:   _tmp = (_r[rd] * 1 + 0) ^ 0  // identity transform
              _tmp2 = (_tmp & _tmp) | _tmp  // idempotent
              if _tmp2 == _tmp2:  // always true — opaque prefix
                  if _tmp != 0: jump target  // actual condition
```

#### 3.1.2 Arithmetic Predicate Transforms

For comparison-based branching (`VM_JMP_EQ`, `VM_JMP_LT`, etc.), use arithmetic transforms:

```python
# VM_JMP_EQ (jump if rd == rs1)
# Obfuscated evaluation:
_tmp = _r[_rd] - _r[_rs1]       # diff
_tmp2 = (_tmp ^ _tmp) - 1        # -1 if diff==0, -1 always → 0xFFFFFFFF
_tmp3 = (_tmp2 + 1) & 0xFFFFFFFF  # 0 if diff==0, wraps if diff!=0
_tmp4 = _r[_rd] | 0
if (_tmp4 == _r[_rd]):  # opaque true
    if _tmp3 == 0:  # REAL condition: jump if 0 (regs equal)
        jump target

# VM_JMP_LT (jump if rd < rs1)
# Signed comparison obfuscation:
_tmp = _r[_rd] - _r[_rs1]  # compute difference
_tmp2 = (_tmp ^ _tmp) & 0  # constant 0 (opaque)
_tmp3 = _r[_rd] & 0xFFFFFFFF  # mask
_tmp4 = _r[_rs1] & 0xFFFFFFFF
# Real check using sign bit of difference
_tmp5 = (_tmp >> 31) & 1  # sign bit: 1 if rd < rs1 (signed)
_tmp6 = (_tmp5 * 2) ^ _tmp5  # identity on sign bit
if _tmp6 & 1:  # conditional branch on sign bit
    jump target
```

#### 3.1.3 VM_JMP_TABLE (Switch Dispatch)

Implements indirect branching via an offset table, similar to compiler-generated switch jump tables:

```
Encoding: Extended
Format:   [TAG=0xCE] [OP=109] [IDX_REG(1)] [TABLE_ADDR(4)] [DEFAULT_OFFSET(4)]

Semantics:
  _idx = _r[idx_reg]
  _table_base = _code + table_addr  # pointer into code itself
  _entry_size = 4  # 4-byte relative offsets
  if 0 <= _idx < table_length:
      _offset = read_i32(_table_base + _idx * _entry_size)
      _ip += _offset
  else:
      _ip += default_offset
```

**Anti-analysis benefit**: Jump table targets are encoded as data interleaved with code. Static analysis cannot determine the set of possible targets without modeling the index register's value range. Combined with opcode shuffling, the table entries appear as arbitrary 4-byte values in the code stream.

#### 3.1.4 VM_JMP_INDIRECT (Register-Indirect Branch)

```
Encoding: Medium (4B)
Format:   [TAG=0x5C] [OP=108] [TGT_REG(4)] [RSVD(4)] [OFFSET(16)]

Semantics:
  _target_ip = _r[tgt_reg]
  if _target_ip < 0 or _target_ip >= _n:
      _target_ip = 0  // clamp to prevent OOB (anti-crash)
  _ip = _target_ip
```

This enables:
- **Computed goto**: target address computed at runtime
- **Return-oriented-like dispatch**: simulate ROP chains within the VM
- **State machine dispatch**: the current state register determines the next basic block

### 3.2 CFG Reconstruction Resistance

The combination of these techniques makes static CFG reconstruction infeasible:

| Technique | CFG Impact | Static Analysis Difficulty |
|-----------|-----------|---------------------------|
| `VM_JMP_INDIRECT` | Targets unknown | Must track register values across execution |
| `VM_JMP_TABLE` | Multiple targets | Must model index range; table is data, not code |
| Obfuscated conditions | Condition semantics hidden | Must symbolically evaluate arithmetic transforms |
| Exception handlers | Implicit edges everywhere | Must model exception propagation |
| Variable-length encoding | Instruction boundaries unknown | Must decode before any CFG analysis |

---

## 4. Data Flow Obfuscation via Register Spilling

### 4.1 VM Stack Architecture

Add a dedicated **spill stack** to the VM state:

```python
# In interpreter initialization:
_spill_stack = []    # Python list as VM stack
_spill_sp = 0        # stack pointer (conceptual)
_spill_count = 0     # number of active spills
_spill_threshold = random.randint(8, 16)  # random spill trigger
_spill_interval = 0  # cycle counter for pseudo-random triggering
```

### 4.2 Spill/Restore Instructions

#### VM_SPILL (120)

```
Format:   Short (2B)
Encoding: [TAG=0x08] [OP(4)=0x08] [RD(4)] [RSVD(4)]

Semantics:
  _spill_stack.append(('reg', _rd, _r[_rd]))
  # Optionally clear the register to break data flow
  if _spill_mode == 'clear':
      _r[_rd] = None
```

#### VM_RESTORE (121)

```
Format:   Short (2B)
Encoding: [TAG=0x09] [OP(4)=0x09] [RD(4)] [RSVD(4)]

Semantics:
  # Search spill stack for most recent spill of _rd
  for _i in range(len(_spill_stack) - 1, -1, -1):
      _entry = _spill_stack[_i]
      if _entry[0] == 'reg' and _entry[1] == _rd:
          _r[_rd] = _entry[2]
          _spill_stack.pop(_i)
          break
```

#### VM_SPILL_MANY (122)

```
Format:   Medium (4B)
Encoding: [TAG=0x5A] [OP=122] [BASE_REG(4)] [COUNT(4)] [MASK(16)]

Semantics:
  _mask = _imm  # bitmask of registers to spill, relative to base_reg
  for _bit in range(16):
      if _mask & (1 << _bit):
          _reg = _base_reg + _bit
          _spill_stack.append(('reg', _reg, _r[_reg]))
          if _spill_mode == 'clear':
              _r[_reg] = None
```

#### VM_RESTORE_MANY (123)

```
Format:   Medium (4B)
Encoding: [TAG=0x5B] [OP=123] [RESERVED(8)] [COUNT(16)]

Semantics:
  _count = _imm & 0xFFFF
  for _ in range(min(_count, len(_spill_stack))):
      _r[_spill_stack[-1][1]] = _spill_stack[-1][2]
      _spill_stack.pop()
```

### 4.3 Spilling Algorithm

The compiler inserts spill/restore instructions at compile time using a heuristic model of register pressure:

```python
def insert_spills(vm_code, reg_liveness, config):
    """
    vm_code: bytearray of encoded instructions
    reg_liveness: dict mapping instruction_idx → set of live registers
    config: SpillConfig with thresholds
    """
    new_code = bytearray()
    spill_pressure = 0
    cycle_count = 0
    rng = random.Random(config.seed)
    
    for idx, (instr, live_regs) in enumerate(zip(vm_code, reg_liveness)):
        cycle_count += 1
        reg_count = len(live_regs)
        
        # Trigger 1: Register pressure exceeds threshold
        if reg_count > config.pressure_threshold:
            # Spill excess registers
            excess = reg_count - config.target_pressure
            spill_regs = sorted(live_regs, key=lambda r: rng.random())[:excess]
            new_code.extend(emit_spill_many(spill_regs[0], len(spill_regs), 
                                           mask_from_regs(spill_regs)))
            spill_pressure += len(spill_regs)
        
        # Trigger 2: Pseudo-random interval
        if cycle_count % config.spill_interval == 0 and live_regs:
            if rng.random() < config.spill_probability:
                spill_count = min(rng.randint(1, 3), len(live_regs))
                spill_regs = rng.sample(sorted(live_regs), spill_count)
                new_code.extend(emit_spill_many(spill_regs[0], len(spill_regs),
                                               mask_from_regs(spill_regs)))
                spill_pressure += spill_count
        
        # Trigger 3: Opaque predicate-based
        if rng.random() < config.opaque_spill_rate:
            # Insert an opaque check that triggers spill
            new_code.extend(emit_opaque_spill_guard(live_regs, rng))
        
        # Emit the original instruction
        new_code.extend(instr)
        
        # Restore balancing
        if spill_pressure > 0 and rng.random() < config.restore_probability:
            restore_count = min(spill_pressure, rng.randint(1, 3))
            new_code.extend(emit_restore_many(restore_count))
            spill_pressure -= restore_count
    
    # Restore any remaining spilled registers at function exit
    if spill_pressure > 0:
        new_code.extend(emit_restore_many(spill_pressure))
    
    return new_code
```

### 4.4 Triggering Heuristics

| Heuristic | Trigger Condition | Effect |
|-----------|------------------|--------|
| Register pressure | `live_regs > 16` | Spill until ≤ 12 |
| Cycle interval | Every `random(5, 15)` instructions | Unpredictable spilling |
| Opaque predicate | Always-true check | Appears conditional but always spills |
| Data-dependent | Value of specific register modulo N | Attacker must track value |
| Call boundary | Before/after CALL instructions | Simulates callee-save convention |

### 4.5 Data Flow Analysis Resistance

- **Def-use chain breaking**: When a register is spilled and cleared (`_r[rd] = None`), the definition is disconnected from subsequent uses. An adversary must track the spill stack contents.
- **Register renaming**: Spill/restore sequences effectively rename registers across the stack boundary. Two uses of the same register before and after a spill may refer to different values.
- **Stack depth tracking**: The spill stack depth becomes part of the implicit VM state, adding a state dimension that data-flow analysis must model.

---

## 5. Self-Modifying Code

### 5.1 Runtime Code Patching: `VM_PATCH_INSTR`

**Semantics**: XOR-patch a range of the instruction stream at runtime. The patch key is computed from runtime values, making the final code content unpredictable at compile time.

```
Encoding: Extended
Format:   [TAG=0xD2] [OP=130] [OFFSET_REG(1)] [LEN_REG(1)] [KEY_REG(1)] [RESERVED(3)]

Semantics:
  _patch_offset = _r[offset_reg]         # byte offset into _code
  _patch_len = _r[len_reg]               # length in bytes
  _patch_key = _r[key_reg]               # key (may be transformed)
  
  # Transform key to derive patch bytes
  _key_bytes = bytes([(_patch_key >> (8*i)) & 0xFF for i in range(min(_patch_len, 8))])
  _key_stream = (_key_bytes * ((_patch_len // len(_key_bytes)) + 1))[:_patch_len]
  
  # Apply XOR patch
  for _i in range(_patch_len):
      _code[_patch_offset + _i] ^= _key_stream[_i]
```

### 5.2 Opcode Map Patching: `VM_PATCH_OPCODE`

**Semantics**: Modify the inverse opcode map at runtime. This changes the meaning of shuffled opcodes seen later in execution.

```
Format:   Medium (4B)
Encoding: [TAG=0x53] [OP=131] [SHUFFLED_OP(4)] [NEW_CANONICAL(4)] [RESERVED(16)]

Semantics:
  _shuf = _rd       # the shuffled opcode to remap
  _new_op = _rs1    # new canonical opcode value
  _map[_shuf] = _new_op  # update inverse map
```

**Security impact**: After `VM_PATCH_OPCODE`, all subsequent occurrences of `_shuf` in the instruction stream execute a different operation. An adversary who has decoded the instruction stream up to this point must re-decode all subsequent instructions with the updated mapping. This forces iterative re-analysis.

### 5.3 Code Segment Encryption: `VM_ENCRYPT_SEG` / `VM_DECRYPT_SEG`

**Semantics**: XOR-encrypt/decrypt a contiguous region of the code bytearray. Encrypted regions appear as random noise to static analysis and cannot be decoded without the runtime key.

```
Format:   Extended
Encoding: [TAG=0xD4] [OP=132/133] [OFFSET_REG(1)] [LEN_REG(1)] [KEY_REG(1)] [RESERVED(3)]

Semantics for VM_ENCRYPT_SEG:
  _seg_offset = _r[offset_reg]
  _seg_len = _r[len_reg]
  _key = _r[key_reg]
  
  # Derive key stream from register value + cycle count
  _seed = _key ^ _cycle
  _rng_state = (_seed * 1103515245 + 12345) & 0x7FFFFFFF
  for _i in range(_seg_len):
      _rng_state = (_rng_state * 1103515245 + 12345) & 0x7FFFFFFF
      _code[_seg_offset + _i] ^= (_rng_state >> 16) & 0xFF
```

### 5.4 Conditional Self-Modification Triggers

Self-modification is triggered by one or more of these conditions:

```python
# Pseudo-random instruction-count-based trigger
if _cycle % random.randint(20, 50) == 0:
    _patch_offset = _cycle % (_n - 16)
    _patch_key = _patch_offset ^ (_cycle * 0xDEADBEEF)
    _code[_patch_offset : _patch_offset + 8] = _derive_patch(_patch_key)

# Data-dependent trigger
if isinstance(_r[5], int) and _r[5] % 7 == 0:
    _patch_region = _r[5] % _n
    _code[_patch_region] ^= 0xFF  # flip opcode byte

# Opaque predicate guard
# Always-executed check that appears conditional
_tmp = _r[3] & 0xFFFFFFFF
if (_tmp ^ _tmp) == 0:  # always true
    _r[4] = (_r[4] ^ _r[3])  # compute key from unrelated values
    _code[_r[4] % _n] ^= _r[3] & 0xFF
```

### 5.5 Integration Points

Self-modification must not destabilize execution. Safety constraints:

1. **Never overwrite the currently executing instruction or its decoder**
   - Patch offset must be outside the current `_ip ± 16` window
   - Guard: `if abs(_patch_offset - _ip) > 16: apply_patch()`

2. **Never patch a region that contains pending exception handler metadata**
   - Exception handler table is stored separately from code

3. **Allow disabling**: A VM flag `VM_FLAG_DISABLE_SMC` can be set to prevent self-modification

4. **Seeded determinism**: For testability, self-modification can be seeded so identical runs produce identical modifications

### 5.6 Security Analysis

| Property | Effect on RE |
|----------|-------------|
| **Temporal instability** | The same instruction stream produces different code at different execution times. |
| **Key hiding** | Patch keys are derived from runtime values, not stored in the binary. |
| **Opcode remapping** | Prior opcode analysis becomes invalid after remap. |
| **Encrypted regions** | Sections of code are never decrypted in memory simultaneously. |
| **Integration with opaque predicates** | Self-modification appears conditional (but always triggers), adding apparent branches to analysis. |

---

## 6. Integration Architecture

### 6.1 Compilation Pipeline Changes

```
Source Code
    │
    ▼
[Python Compiler (existing)]
    │
    ▼
[Standard VM Bytecode (fixed-size)]
    │
    ▼
[ISA Expander]
    │  ├─ Detect indirect call patterns → emit VM_CALL_INDIRECT
    │  ├─ Detect method calls → emit VM_CALL_VTABLE
    │  └─ Detect try/except → emit VM_TRY/CATCH/THROW/END_TRY
    │
    ▼
[Control Flow Obfuscator]
    │  ├─ Replace direct JMP with JMP_INDIRECT where possible
    │  ├─ Decompose conditions with arithmetic transforms
    │  ├─ Insert jump tables (VM_JMP_TABLE) for switches
    │  └─ Add obfuscated condition prefixes to branches
    │
    ▼
[Register Spilling Pass]
    │  ├─ Compute liveness analysis
    │  ├─ Insert SPILL/RESTORE at pseudo-random intervals
    │  └─ Balance spill pressure
    │
    ▼
[Self-Modification Injector]
    │  ├─ Insert PATCH_INSTR at computed intervals
    │  ├─ Insert opcode remapping events
    │  └─ Insert encrypt/decrypt segments
    │
    ▼
[Variable-Length Encoder]
    │  ├─ Select encoding class per instruction
    │  ├─ Emit tag byte + variable-length payload
    │  └─ Update instruction count metadata
    │
    ▼
[Opcode Shuffle & Serialize (existing)]
    │
    ▼
[Encrypt & Blob Output (existing)]
```

### 6.2 C/C++ Integration: Header Changes (`vm.h`)

```c
#ifndef CRYPTO_VM_H
#define CRYPTO_VM_H

#include "crypto/common.h"
#include <stdint.h>

// --- Existing constants ---
#define VM_REGS          64
#define VM_MAX_CONSTS    256
#define VM_MAX_NAMES     256

// --- OLD: fixed instruction size (remove or keep as legacy fallback) ---
#define VM_INSTR_SIZE    8
#define VM_INSTR_SIZE_MIN 2  // minimum variable-length size
#define VM_INSTR_SIZE_MAX 64 // maximum variable-length size

// --- Extended opcode enum (see section 2.1 for full enum) ---

// --- Instruction format helpers (for variable-length parsing) ---
typedef enum {
    VL_CLASS_SHORT   = 0,
    VL_CLASS_MEDIUM  = 1,
    VL_CLASS_LONG    = 2,
    VL_CLASS_EXTENDED = 3,
} VlLengthClass;

// --- VmInstr (legacy struct — still used for serialization/display) ---
typedef struct __attribute__((packed)) {
    uint8_t  op;
    uint8_t  rd;
    uint8_t  rs1;
    uint8_t  rs2;
    int32_t  imm;
} VmInstr;

// --- Extended compilation config ---
typedef struct {
    int enable_opaque_predicates;
    int seed;
    
    // Feature flags
    int enable_indirect_calls;
    int enable_virtual_calls;
    int enable_exceptions;
    int enable_var_length_encoding;
    int enable_conditional_obfuscation;
    int enable_register_spilling;
    int enable_self_modifying_code;
    
    // Spilling config
    int spill_pressure_threshold;   // default 12
    int spill_target_pressure;      // default 8
    int spill_interval;             // default 10
    float spill_probability;        // default 0.3
    
    // Self-modification config
    int smc_min_interval;           // default 20
    int smc_max_interval;           // default 50
    
    // Conditional obfuscation config
    int cond_obfuscation_strength;  // 0=off, 1=basic, 2=aggressive
} VmCompileConfig;

extern ExitCode vm_compile_source_ex(const char *source, size_t source_len,
                                      VmProgram *prog, VmCompileConfig *cfg);

// --- Variable-length encoding ---
// Encode a single canonical instruction into variable-length format
extern size_t vm_encode_var_length(uint8_t *out, size_t out_max,
                                    uint8_t canonical_op,
                                    uint8_t rd, uint8_t rs1, uint8_t rs2,
                                    int32_t imm);

// Decode the next variable-length instruction; returns size consumed
extern size_t vm_decode_var_length(const uint8_t *code, size_t code_len,
                                    uint8_t *op_canonical,
                                    uint8_t *rd, uint8_t *rs1, uint8_t *rs2,
                                    int32_t *imm);

// --- Register spilling pass ---
extern ExitCode vm_pass_spill_registers(VmProgram *prog, uint8_t *code,
                                         int *code_len, int seed);

// --- Self-modification pass ---
extern ExitCode vm_pass_inject_self_modifying(VmProgram *prog, uint8_t *code,
                                               int *code_len,
                                               VmCompileConfig *cfg);

// --- Conditional branch obfuscation pass ---
extern ExitCode vm_pass_obfuscate_conditions(VmProgram *prog, uint8_t *code,
                                              int *code_len, int strength);

// --- Existing functions ---
ExitCode vm_program_init(VmProgram *prog);
void vm_program_free(VmProgram *prog);
ExitCode vm_compile_source(const char *source, size_t source_len,
                            VmProgram *prog, int opaque, int seed = -1);
ExitCode vm_serialize(const VmProgram *prog, Buffer *out);
ExitCode vm_deserialize(const unsigned char *data, size_t size,
                         VmProgram *prog);
int vm_encrypt_blob(const unsigned char *plaintext, int plaintext_len,
                    unsigned char **ciphertext, int *ciphertext_len);

#endif
```

### 6.3 Interpreter Changes (`vm_interp_py.h`)

The interpreter gains a section for the new opcodes. The main dispatch loop grows a variable-length decoder:

```python
def _vm_run(_code, _consts, _names, _globals, _locals, _map, _op_key):
    import sys, random
    if sys.gettrace() is not None: sys.exit(1)
    
    # --- Initialization ---
    _reg_map = list(range(64))
    random.shuffle(_reg_map)
    _r = [None] * 64
    _ip = 0
    _cycle = 0
    _n = len(_code)
    _b = __builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__
    
    # --- New state for enhanced features ---
    _spill_stack = []          # register spilling stack
    _handler_stack = []        # exception handler frames
    _vm_flags = 0              # flags (SMC enable, etc.)
    _smc_key = random.getrandbits(32)  # self-modification key
    
    # --- Forward declare variable-length decoder ---
    def _decode_at(_ip):
        _tag = _code[_ip] ^ (_op_key[_ip % len(_op_key)])
        _class = (_tag >> 6) & 0x3
        # ... variable-length decoding (see section 1.4) ...
        return _op_canonical, _rd, _rs1, _rs2, _imm, _size
    
    # --- Main dispatch ---
    while _ip < _n:
        _cycle += 1
        _op, _rd, _rs1, _rs2, _imm, _ilen = _decode_at(_ip)
        
        # [existing opcode handling...]
        
        # --- NEW: Indirect & Virtual Call ---
        elif _op == 80:  # VM_CALL_INDIRECT
            _fn = _r[_rs1]
            _argc = _imm & 0xFFFF
            _args = tuple(_r[_rs1 + 1 + _i] for _i in range(_argc))
            _r[_rd] = _fn(*_args)
        
        elif _op == 81:  # VM_CALL_VTABLE
            _obj = _r[_rs1]
            _vtable = _r[_rs1 + 1]
            _method = _vtable[_imm & 0xFFFF]
            _argc = (_imm >> 16) & 0xFFFF
            _args = tuple(_r[_rs1 + 2 + _i] for _i in range(_argc))
            _r[_rd] = _method(_obj, *_args)
        
        # --- NEW: Exception Handling ---
        elif _op == 90:  # VM_TRY
            _handler_stack.append({
                'start': _ip,
                'end': _ip + _imm,
                'catch_ip': None,
                'catch_type': None
            })
        
        elif _op == 91:  # VM_CATCH
            if _handler_stack:
                _handler_stack[-1]['catch_type'] = _r[_rd]
                _handler_stack[-1]['catch_ip'] = _ip + _ilen
        
        elif _op == 92:  # VM_THROW
            _exc_val = _r[_rs1]
            _found = False
            for _h in reversed(_handler_stack):
                if _h['start'] <= _ip <= _h['end']:
                    if (_h['catch_type'] is None or
                        isinstance(_exc_val, _h['catch_type'])):
                        _ip = _h['catch_ip']
                        _r[_rs1] = _exc_val
                        _found = True
                        break
            if not _found:
                raise _exc_val
            continue  # don't advance _ip
        
        elif _op == 93:  # VM_END_TRY
            if _handler_stack:
                _handler_stack.pop()
        
        # --- NEW: Control Flow Obfuscation ---
        elif _op == 100:  # VM_JMP_IF_TRUE (obfuscated)
            # Obfuscated evaluation
            _v = _r[_rd]
            _t1 = (_v & _v) | _v       # identity: _v
            _t2 = (_t1 ^ 0) + 0         # identity
            _t3 = _t2 ^ _t2             # always 0 (opaque predicate guard)
            if _t3 == 0:                # always taken
                if _t2:                 # REAL condition
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        
        elif _op == 102:  # VM_JMP_EQ (obfuscated)
            _d = _r[_rd] - _r[_rs1]
            _m = (_d - 1) ^ (-1)        # invert and mask
            _o = _r[_rd] ^ _r[_rd]      # 0 (opaque)
            if _o == 0:                 # always
                if _d == 0:             # REAL condition
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        
        elif _op == 108:  # VM_JMP_INDIRECT
            _target = _r[_rd]
            if 0 <= _target < _n:
                _ip = _target
            else:
                _ip = 0  # safe clamp
            continue
        
        elif _op == 109:  # VM_JMP_TABLE
            _idx = _r[_rd]
            _table_base = _imm & 0xFFFF
            _default_off = (_imm >> 16) & 0xFFFF
            _num_entries = _rs1
            if 0 <= _idx < _num_entries:
                _entry_off = _table_base + _idx * 4
                if _entry_off + 4 <= _n:
                    _offset = (_code[_entry_off] |
                               (_code[_entry_off+1] << 8) |
                               (_code[_entry_off+2] << 16) |
                               (_code[_entry_off+3] << 24))
                    _ip += _offset
                else:
                    _ip += _default_off
            else:
                _ip += _default_off
            continue
        
        # --- NEW: Register Spilling ---
        elif _op == 120:  # VM_SPILL
            _spill_stack.append(_r[_rd])
        
        elif _op == 121:  # VM_RESTORE
            if _spill_stack:
                _r[_rd] = _spill_stack.pop()
        
        elif _op == 122:  # VM_SPILL_MANY
            _mask = _imm
            for _b in range(16):
                if _mask & (1 << _b):
                    _spill_stack.append(_r[_rd + _b])
                    _r[_rd + _b] = None  # clear to break data flow
        
        elif _op == 123:  # VM_RESTORE_MANY (not used in spilling, but keep for full implementation)
            _cnt = _imm & 0xFF
            for _ in range(min(_cnt, len(_spill_stack))):
                _val = _spill_stack.pop()
                # Don't know which register — restore to a temp
                # (in practice, RESTORE_MANY pairs with SPILL_MANY metadata)
        
        # --- NEW: Self-Modifying Code ---
        elif _op == 130:  # VM_PATCH_INSTR
            _off = _r[_rd]
            _len = _r[_rs1]
            _key = _r[_rs2]
            if _off >= 0 and _off + _len <= _n:
                if abs(_off - _ip) > 16:  # safety: don't patch self
                    _ks = _key.to_bytes(8, 'little')
                    for _i in range(min(_len, 8)):
                        _code[_off + _i] ^= _ks[_i % len(_ks)]
        
        elif _op == 133:  # VM_DECRYPT_SEG
            _off = _r[_rd]
            _len = _r[_rs1]
            _key = _r[_rs2]
            if _off >= 0 and _off + _len <= _n and abs(_off - _ip) > 16:
                _seed = _key ^ _cycle
                _rng = (_seed * 1103515245 + 12345) & 0x7FFFFFFF
                for _i in range(_len):
                    _rng = (_rng * 1103515245 + 12345) & 0x7FFFFFFF
                    _code[_off + _i] ^= (_rng >> 16) & 0xFF
        
        # --- Advance instruction pointer ---
        _ip += _ilen
```

### 6.4 Compiler Changes (`vm_compile.cpp`)

New compilation pass order in `vm_compile_source`:

```c
ExitCode vm_compile_source_ex(const char *source, size_t source_len,
                               VmProgram *prog, VmCompileConfig *cfg) {
    // Step 1: Standard compilation (existing)
    // Produces fixed-size VmInstr array through Python compiler
    RET_ERR(vm_compile_source_standard(source, source_len, prog, cfg));
    
    // Step 2: ISA Expansion
    if (cfg->enable_indirect_calls || cfg->enable_virtual_calls || cfg->enable_exceptions) {
        // Transform bytecode to use new instructions
        // (operates on VmInstr array before encoding)
        RET_ERR(vm_pass_isa_expand(prog, cfg));
    }
    
    // Step 3: Control Flow Obfuscation
    if (cfg->enable_conditional_obfuscation) {
        RET_ERR(vm_pass_obfuscate_conditions(prog, cfg->cond_obfuscation_strength));
    }
    
    // Step 4: Convert to byte array for further passes
    uint8_t *code_buf;
    int code_len;
    vm_instrs_to_bytes(prog, &code_buf, &code_len);
    
    // Step 5: Register Spilling
    if (cfg->enable_register_spilling) {
        RET_ERR(vm_pass_spill_registers(prog, code_buf, &code_len, cfg));
    }
    
    // Step 6: Self-Modification Injection
    if (cfg->enable_self_modifying_code) {
        RET_ERR(vm_pass_inject_self_modifying(prog, code_buf, &code_len, cfg));
    }
    
    // Step 7: Variable-Length Encoding
    if (cfg->enable_var_length_encoding) {
        uint8_t *vl_buf;
        int vl_len;
        RET_ERR(vm_encode_program(code_buf, code_len, &vl_buf, &vl_len));
        // Replace code_buf with variable-length encoded version
        free(code_buf);
        code_buf = vl_buf;
        code_len = vl_len;
    }
    
    // Step 8: Opcode shuffle & serialize (existing)
    RET_ERR(vm_finalize(prog, code_buf, code_len));
    
    free(code_buf);
    return EXIT_OK;
}
```

---

## 7. Orthogonal Composition & Multiplicative Obfuscation

The improvements are designed to be **orthogonal** — each targets a different dimension of the analysis problem:

| Technique | Analysis Dimension | Complements |
|-----------|--------------------|-------------|
| Variable-length encoding | Static disassembly | All others — without correct decode, no analysis begins |
| Indirect/virtual calls | Call graph reconstruction | Spilling obscures register state feeding call targets |
| Exception handling | CFG reconstruction | Self-modifying code can patch handler targets at runtime |
| Obfuscated conditions | Condition logic understanding | Spilling can spill the condition register before the branch |
| Register spilling | Data-flow / def-use chains | Self-modification can spill to encrypted code regions |
| Self-modifying code | Temporal code stability | Variable-length encoding makes patches harder to detect |

**Multiplicative effect example**: An obfuscated conditional branch (opaque transform) → that spills the condition register → the spilled value is restored from a location that was just self-modified → the restore instruction has variable-length encoding. An adversary must simultaneously:
1. Correctly decode variable-length instructions
2. Track register spilling across the stack
3. Symbolically evaluate the opaque arithmetic transform
4. Model the self-modification's effect on the code
5. All this for a single conditional branch

---

## 8. Computational Feasibility

| Component | Runtime Overhead | Notes |
|-----------|-----------------|-------|
| Variable-length decode | +1 tag byte parse per instr | Constant time, minimal |
| Indirect call | Same as regular call + 1 register lookup | Marginal |
| Virtual call | +1 method table lookup | O(1) |
| Exception handling | Zero cost unless exception thrown | Try block overhead ~1 stack push |
| Obfuscated conditions | +3-5 ALU ops per branch | Constant small overhead |
| Register spilling | +1 stack push/pop per spill | Linear in spill count |
| Self-modifying code | +XOR loop per patch | O(n) in patch size, small n |

All techniques are **computationally feasible** at runtime. The dominant cost remains the Python interpreter overhead, not these obfuscation primitives.

---

## 9. Security Analysis Summary

| Threat Model | Current Protection | With Improvements |
|-------------|-------------------|-------------------|
| Static disassembly | Fixed 8B boundaries → trivial split | Variable-length → must implement full decoder |
| Opcode identification | Randomized mapping → 256! permutations | Same, plus runtime remapping (PATCH_OPCODE) |
| Call graph reconstruction | Direct JMP only | Indirect calls + virtual dispatch + table dispatch |
| CFG reconstruction | ~5 branch types, direct targets | 10+ branch types, indirect targets, exception edges |
| Data flow analysis | Linear register trace | Spill stack breaks def-use chains |
| Memory/state analysis | Minimal VM state | Spill stack + handler stack + SMC state |
| Pattern matching | Fixed instruction patterns | Variable-length + polymorphism via SMC |
| Emulation detection | Opaque predicates only | SMC + encrypted code segments |
| Time-based analysis | Stable execution | SMC changes code temporally |
| Symbolic execution | Single path per branch | Obfuscated conditions increase solver complexity |

---

## Appendix: Implementation Checklist

- [ ] `vm.h`: Add new opcode enum values, VmCompileConfig struct
- [ ] `vm_py.h`: Update Python compiler to emit new instructions
- [ ] `vm_interp_py.h`: Add variable-length decoder + new opcode handlers
- [ ] `vm_compile.cpp`: Add compilation passes (ISA expand, CF obfuscate, spill, SMC, var-encode)
- [ ] `vm_stub.cpp`: No changes needed (stub just embeds interpreter)
- [ ] New file `vm/spill.cpp`: Register spilling pass implementation
- [ ] New file `vm/smc.cpp`: Self-modifying code pass implementation
- [ ] New file `vm/obfcond.cpp`: Obfuscated condition pass implementation
- [ ] New file `vm/vlencode.cpp`: Variable-length encoder implementation
- [ ] `tests/test_vm.cpp`: Add test cases for each new instruction type
- [ ] `CMakeLists.txt`: Add new source files
