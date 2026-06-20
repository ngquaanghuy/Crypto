Đây là dự án đầu tay của tôi nên có thể bị lỗi

Nếu bạn là người dùng linux hãy sử dụng lệnh sau để cài đặt
```
git clone https://github.com/ngquaanghuy/Crypto
cd Crypto
cmake -S . -B build && cmake --build build -j$(nproc)
```

Nếu bạn là người dùng Window/MacOS hãy sử dụng docker đã được cấu hình sẵn trong dự án với Arch

# Đảm bảo các package

- CMake => 3.16 trở lên
- C++ 20
- OpenSSL
- ZLIB
- Python 3.10 trở lên
- Brotli

# Cảnh báo
- Chỉ sử dụng với dữ liệu nhảy cảm
- --obf hay xung đột với --vm
- Không sử dụng file quá lớn > 10kb vì hiện tại dự án chưa có split thành file nhỏ

# VM (Register Virtual Machine)

Khi sử dụng `--vm`, toàn bộ source code được biên dịch sang bytecode và chạy trên một Register VM interpreter được nhúng trong stub. VM interpreter hỗ trợ nhiều kỹ thuật chống phân tích:

## Cách sử dụng cơ bản

```bash
# VM cơ bản
crypto protect --vm --keygen 32 script.py

# VM + obfuscation
crypto protect --vm --obf all --keygen 32 script.py

# VM + mật độ obfuscation cao
crypto protect --vm --obf-density 2.5 --keygen 32 script.py
```

## Opcode Shuffling

Toàn bộ opcode map (256 entries) được shuffle ngẫu nhiên mỗi lần compile. Interpreter dùng opcode map để decode instruction, đảm bảo không thể static-analyze bytecode nếu không có map.

## Self-Modifying Code (SMC)

Tự động inject các instruction `VM_PATCH_INSTR`, `VM_PATCH_OPCODE`, `VM_ENCRYPT_SEG`, `VM_DECRYPT_SEG` vào instruction stream với khoảng cách ngẫu nhiên (20-50 instructions). Các instruction này cho phép VM tự modify code tại runtime, chống debugger và emulator.

## Register Spilling

Khi áp lực register vượt ngưỡng (mặc định 12), VM tự động spill register xuống stack và restore lại sau. Các spill/restore được inject với interval và probability ngẫu nhiên, gây khó khăn cho data-flow analysis.

## Conditional Obfuscation

Các conditional branch được biến đổi thành opaque-predicate guarded jumps (`VM_JMP_IF_TRUE_OBF`, `VM_JMP_IF_FALSE_OBF`, `VM_JMP_EQ/NE/LT/LE/GT/GE`) với các biểu thức luôn đúng/sai được tạo từ các phép tính bit, giấu control flow thật.

## Variable-Length Encoding

Bytecode được encode với độ dài instruction thay đổi (2-72 bytes) thay vì fixed 8 bytes. Kết hợp với XOR key rolling theo từng byte, làm cho việc xác định instruction boundary trở nên bất khả thi nếu không có key và opcode map.

## Polymorphic Encoding

Các instruction được encode với nhiều variant khác nhau (bit layout, interleaving, size), mỗi instruction có thể xuất hiện với 1 trong 4 dạng mã hóa. Poly decoder tự động phát hiện variant khi decode.

## Rotating Dispatch Loop

Main dispatch loop sử dụng 4 mode dispatch khác nhau (guarded checks, rotating state machine) để chống static analysis của control flow. Kết hợp với periodic XOR key rotation cho register bank (mỗi 32 cycles).

## Register XOR Garbler

Toàn bộ 64 register được lưu trong split-register bank (`_r_even[32]` + `_r_odd[32]`) với XOR key riêng cho mỗi register. Key được rotate định kỳ (mỗi 32 cycles). Register value luôn được XOR-encrypt khi lưu và XOR-decrypt khi đọc.

## Type Tracking

VM theo dõi kiểu dữ liệu của từng register (`_r_type[64]` array, 0=non-int, 1=int) để tránh isinstance() check không cần thiết, cải thiện performance.

## Register Caching

Pre-read `_rd_val`, `_rs1_val`, `_rs2_val` trước khi gọi handler, post-writeback `_r_set(_rd, _rd_val)` chỉ khi `_rd_modified=True`. Loại bỏ ~2 function calls (`_r_get`/`_r_set`) per instruction cho ~70 simple handlers (arithmetic, comparison, load/store, iteration, pattern matching).

## Control Flow Integrity (CFI)

Khi bật (`--cfi`), VM inject `VM_CFI_CHECK` instruction định kỳ để tính checksum của code block và so sánh với checksum đã compile. Phát hiện code modification (breakpoint, patch) tại runtime.

## Constant Pool Encryption

Khi bật (`--const-enc`), toàn bộ string constants trong VM bytecode được XOR-encrypt với key 16-byte riêng. Key được lưu trong serialized data và chỉ decrypt khi cần.

# Virtual RAM (--vram-enable)

Virtual RAM là một vùng nhớ 4 KB được XOR-garbled trong VM runtime. Dữ liệu trong vRAM luôn được mã hóa với key rolling 16-byte — dump memory dump cũng vô dụng.

**Lưu ý**: vRAM **mặc định bị tắt**. Phải dùng `--vram-enable` để bật.

## Kiến trúc

```
VM RAM: [BYTE_0] [BYTE_1] ... [BYTE_4095]  ← 4 KB
            ⊕        ⊕            ⊕
            │        │            │
         KEY[0]   KEY[1]      KEY[15]      ← 16-byte rolling key
```

Mỗi byte trong vRAM được XOR với `KEY[addr & 15]`:
- **Read**: `value = RAM[addr] ⊕ KEY[addr & 15]`
- **Write**: `RAM[addr] = value ⊕ KEY[addr & 15]`

## Cách sử dụng

```bash
# Bật vRAM
crypto protect --vm --vram-enable script.py

# Bật vRAM + garble định kỳ
crypto protect --vm --vram-enable --vram-garble script.py

# Tùy chỉnh interval garble (mặc định 80-200 instructions)
crypto protect --vm --vram-enable --vram-garble --vram-garble-interval 50-150 script.py
```

## Opcodes

| Opcode | Tên | Chức năng |
|--------|-----|-----------|
| 143 | `VM_LOAD_B` | Load 1 byte từ vRAM[rs1] → rd |
| 144 | `VM_STORE_B` | Store byte rd & 0xFF → vRAM[rs2] |
| 145 | `VM_LOAD_W` | Load 4 byte little-endian từ vRAM[rs1] → rd |
| 146 | `VM_STORE_W` | Store 4 byte rd → vRAM[rs2..rs2+3] |
| 147 | `VM_RAM_GARBLE` | Re-key toàn bộ 4KB vRAM (XOR key rotation) |

## VM_RAM_GARBLE (Periodic Re-key)

Khi bật `--vram-garble`, compile pipeline tự động inject `VM_RAM_GARBLE` vào instruction stream với interval ngẫu nhiên (mặc định 80-200 instructions). Mỗi lần garble:

1. Sinh 16 bytes key mới từ `os.urandom(16)`
2. Re-XOR toàn bộ 4KB: `RAM[i] = RAM[i] ⊕ old_key[i%16] ⊕ new_key[i%16]`
3. Cập nhật key mới

Điều này đảm bảo key luân chuyển liên tục, chống static analysis và memory dump. Tần suất garble có thể được kiểm soát qua `--vram-garble-interval <min>-<max>`.

### Tham số đầy đủ

```
--vram-enable                    Bật Virtual RAM (4 KB XOR-garbled scratch memory)
--vram-garble                    Bật periodic re-key (chỉ với --vram-enable)
--vram-garble-interval <min-max> Khoảng cách giữa các lần garble (mặc định 80-200)
```

# Dự án đã hoàn thành 
