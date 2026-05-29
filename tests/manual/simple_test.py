from typing import Optional, List

def greet(name: str, greeting: Optional[str] = None) -> str:
    if greeting is None:
        greeting = "Hello"
    return f"{greeting}, {name}!"

def factorial(n: int) -> int:
    if n <= 1:
        return 1
    return n * factorial(n - 1)

def main():
    names = ["Alice", "Bob", "Charlie"]
    for name in names:
        msg = greet(name)
        print(msg)
    
    result = factorial(10)
    print(f"factorial(10) = {result}")

if __name__ == "__main__":
    main()
