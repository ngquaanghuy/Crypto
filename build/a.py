DIG = "123456789"
I = range(9)


def scrub(s):
    s = "".join(ch for ch in s if ch in DIG + ".0")
    if len(s) != 81:
        raise ValueError("Cần đúng 81 ký tự Sudoku")
    return s.replace("0", ".")


def idx(k):
    r, c = divmod(k, 9)
    b = (r // 3) * 3 + c // 3
    return r, c, b


def stamp(r, c, n):
    b = (r // 3) * 3 + c // 3
    return (
        ("cell", r, c),
        ("row", r, n),
        ("col", c, n),
        ("box", b, n),
    )


def weave():
    X = {}
    Y = {}
    for k in range(81):
        r, c, _ = idx(k)
        for ch in DIG:
            n = int(ch)
            key = (r, c, n)
            cols = stamp(r, c, n)
            Y[key] = cols
            for col in cols:
                X.setdefault(col, set()).add(key)
    return X, Y


def choose(X):
    return min(X, key=lambda c: len(X[c]))


def cover(X, Y, row):
    trace = []
    for col in Y[row]:
        for other in list(X[col]):
            for shadow in Y[other]:
                if shadow != col:
                    X[shadow].remove(other)
        trace.append(X.pop(col))
    return trace


def uncover(X, Y, row, trace):
    for col in reversed(Y[row]):
        X[col] = trace.pop()
        for other in X[col]:
            for shadow in Y[other]:
                if shadow != col:
                    X[shadow].add(other)


def inject(X, Y, puzzle):
    fixed = []
    for k, ch in enumerate(puzzle):
        if ch == ".":
            continue
        r, c, _ = idx(k)
        row = (r, c, int(ch))
        if any(col not in X for col in Y[row]):
            return None
        fixed.append(row)
        cover(X, Y, row)
    return fixed


def drift(X, Y, path):
    if not X:
        yield list(path)
        return
    col = choose(X)
    if not X[col]:
        return
    for row in list(X[col]):
        path.append(row)
        trace = cover(X, Y, row)
        yield from drift(X, Y, path)
        uncover(X, Y, row, trace)
        path.pop()


def flatten(rows):
    board = [["." for _ in I] for _ in I]
    for r, c, n in rows:
        board[r][c] = str(n)
    return "".join("".join(line) for line in board)


def rows_of(s):
    for r in I:
        yield s[r * 9:(r + 1) * 9]


def cols_of(s):
    for c in I:
        yield "".join(s[c + 9 * r] for r in I)


def boxes_of(s):
    for br in range(0, 9, 3):
        for bc in range(0, 9, 3):
            yield "".join(
                s[(br + dr) * 9 + (bc + dc)]
                for dr in range(3)
                for dc in range(3)
            )


def sane(unit):
    return "".join(sorted(unit)) == DIG


def orbit(s):
    yield from rows_of(s)
    yield from cols_of(s)
    yield from boxes_of(s)


def valid(s):
    return all(sane(u) for u in orbit(s))


def pretty(s):
    out = []
    for r in I:
        if r and r % 3 == 0:
            out.append("------+-------+------")
        line = []
        for c in I:
            if c and c % 3 == 0:
                line.append("|")
            line.append(s[r * 9 + c])
        out.append(" ".join(line))
    return "\n".join(out)


def paradox(puzzle):
    X, Y = weave()
    fixed = inject(X, Y, scrub(puzzle))
    if fixed is None:
        return None
    try:
        tail = next(drift(X, Y, []))
    except StopIteration:
        return None
    ans = flatten(fixed + tail)
    return ans if valid(ans) else None


if __name__ == "__main__":
    maze = (
        "530070000"
        "600195000"
        "098000060"
        "800060003"
        "400803001"
        "700020006"
        "060000280"
        "000419005"
        "000080079"
    )

    ans = paradox(maze)

    if ans is None:
        print("vô nghiệm hoặc input lỗi")
    else:
        print(pretty(ans))
