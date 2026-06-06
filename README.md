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
