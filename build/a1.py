def giai_thua(n):
    # Điều kiện dừng (base case)
    if n == 0 or n == 1:
        return 1
    # Lời gọi đệ quy
    return n * giai_thua(n - 1)

# Chạy thử
so = int(input("Nhập số nguyên dương: "))
print(f"Giai thừa của {so} là: {giai_thua(so)}")

def fibonacci(n):
    # Điều kiện dừng
    if n <= 1:
        return n
    # Gọi đệ quy
    return fibonacci(n - 1) + fibonacci(n - 2)

# Chạy thử
n = int(input("Nhập vị trí Fibonacci: "))
print(f"Số Fibonacci thứ {n} là: {fibonacci(n)}")

def tong(n):
    if n == 0:
        return 0
    return n + tong(n - 1)

print("Tổng từ 1 đến 5 là:", tong(5))
