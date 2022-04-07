def gcd(a, b):
    n, d = a, b
    r = n - d * (n // d)
    while r != 0:
        n = d
        d = r
        r = n - d * (n // d)

    return d


def main():
    a = int(input("a: "))
    b = int(input("b: "))
    print(gcd(a, b))


if __name__ == "__main__":
    main()
