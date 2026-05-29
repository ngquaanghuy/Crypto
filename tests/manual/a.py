def add(a, b):
    return a + b

def subtract(a, b):
    return a - b

def multiply(a, b):
    return a * b

def divide(a, b):
    if b == 0:
        return "Not divisible by zero!"
    return a / b

# Test cases
num1 = 12
num2 = 4
print(f"Adding: {add(num1, num2)}")
print(f"Dividing: {divide(num1, num2)}")
