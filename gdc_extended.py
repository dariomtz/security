def gcd(a, b):
    v, x, y = [a, b], [1, 0], [0, 1]
    lists = [v, x, y]
    i = 0
    next_i = (i + 1) % 2

    while v[next_i] != 0:
        q = v[i] // v[next_i]
        for l in lists:
            l[i] = l[i] - (q * l[next_i])

        i = next_i
        next_i = (i + 1) % 2

    return v[i]


def main():
    a = int(input("a: "))
    b = int(input("b: "))
    print(gcd(a, b))


if __name__ == "__main__":
    main()
