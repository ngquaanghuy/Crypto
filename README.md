Đây là dự án đầu tay của tôi nên có thể bị lỗi

Nếu bạn là người dùng linux hãy sử dụng lệnh sau để cài đặt
```
git clone https://github.com/ngquaanghuy/Crypto
cd Crypto
cmake -S . -B build && cmake --build build -j$(nproc)
```

Nếu bạn là người dùng Window/MacOS hãy sử dụng docker đã được cấu hình sẵn trong dự án với Arch

# Đảm bảo các package

CMake => 3.16 trở lên
C++ 20
OpenSSL
ZLIB
Python 3.10 trở lên

# Cảnh báo
- Chỉ sử dụng với dữ liệu nhảy cảm
- --obf hay xung đột với --vm
- Không sử dụng file quá lớn > 10kb vì hiện tại dự án chưa có split thành file nhỏ

# Dự án đã hoàn thành 
