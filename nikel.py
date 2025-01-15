#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host ctf.mf.grsu.by --port 9040
from pwn import *

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'ctf.mf.grsu.by'
port = int(args.PORT or 9028)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

def parse_coordinates(coord_str):
    try:
        # Remove any single letter followed by " = " if present
        coord_str = re.sub(r"^[a-zA-Z] = ", "", coord_str)
        # Remove parentheses and split by comma
        coord_str = coord_str.strip("()")
        x_str, y_str = coord_str.split(",")
        # Convert to integers
        xx = int(x_str.strip())
        yy = int(y_str.strip())
        return xx, yy
    except (ValueError, AttributeError) as e:
        raise ValueError("Invalid input format. Expected '(x, y)' or '[LETTER] = (x, y)' with integers.") from e

def parse_equation(equation):
    try:
        # Remove any trailing '=' or spaces
        equation = equation.strip().rstrip("=")
        # Regex to match terms like "number*letter" (e.g., "527*P")
        pattern = r"(\d+)\*([a-zA-Z])"
        # Extract matches into a dictionary
        result = {letter: int(number) for number, letter in re.findall(pattern, equation)}
        return result
    except Exception as e:
        raise ValueError("Invalid equation format. Expected terms like 'number*letter'.") from e

def is_on_curve(point, a, b, s):
    if point is None:
        return True
    x, y = point
    return (y**2 - (x**3 + a * x + b)) % s == 0

def add_points(p1, p2, a, s):
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 == y2:
        # Point doubling
        if y1 == 0:
            return None  # Point at infinity
        m = (3 * x1**2 + a) * pow(2 * y1, -1, s) % s
    else:
        # Point addition
        if x1 == x2:
            return None  # Point at infinity
        m = (y2 - y1) * pow(x2 - x1, -1, s) % s

    x3 = (m**2 - x1 - x2) % s
    y3 = (m * (x1 - x3) - y1) % s

    return (x3, y3)

def scalar_multiply(point, scalar, a, b, s):
    result = None
    addend = point

    while scalar:
        if scalar & 1:
            result = add_points(result, addend, a, s)
        addend = add_points(addend, addend, a, s)
        scalar >>= 1

    return result

def solve_problem(coeffs, n, m, k=0, a=1, b=1, s=23):
    P = coeffs.get('P')
    Q = coeffs.get('Q')
    R = coeffs.get('R', None)

    if not is_on_curve(P, a, b, s) or not is_on_curve(Q, a, b, s) or (R and not is_on_curve(R, a, b, s)):
        raise ValueError("Points are not on the curve")

    result = None

    if n > 0:
        result = scalar_multiply(P, n, a, b, s)

    if m > 0:
        result = add_points(result, scalar_multiply(Q, m, a, b, s), a, s)

    if k and k > 0 and R:
        result = add_points(result, scalar_multiply(R, k, a, b, s), a, s)

    return str(result)[1:-1] if result else "None"

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
#
# ********************************************************************
# * We will offer you point P, Q, R (or only P and Q),               *
# *    which lies on curve Ep(a,b).                                  *
# *                                                                  *
# * And you must find n*P + m*Q + k*R (or n*P + m*Q), n, m, k > 0.   *
# * Your answer in format: x,y - Two integers, separated by a comma. *
# * If answer 'a point at infinity', then enter None.                *
# *                                                                  *
# * You are given 50 attempts. Each time is 5 seconds.               *
# ********************************************************************
#
#
# Elliptic Curve defined by Ep(a,b): y^2 = x^3 + a*x + b over Finite Field of size S
#
# P = (28, 30), Q = (12, 2)                       round 0 / 50
# 976*P + 2*Q =

io = start()

for i in range(5):
    (io.recvuntil(b"x^3 + "))
    a = int(io.recvuntil(b"*")[:-1])
    io.recv(4)
    b = int(io.recvuntil(b" ")[:-1])
    io.recvuntil(b"size ")
    S = int(io.recvline().strip())
    io.recvline()
    for _ in range(10):
        line = io.recvline().decode().split("round")[0].strip()
        coords = {}
        for entry in line.split("), "):
            letter = entry[0]
            x, y = parse_coordinates(entry)
            coords[letter] = (x, y)

        problem = io.recvline().decode().strip()
        coeffs = parse_equation(problem)
        ans = solve_problem(coords, coeffs.get("P"), coeffs.get("Q"), coeffs.get("R"), a,b,S)
        io.sendline(ans)
        if "mis" in io.recvline().decode():
            break
    io.recvline()
print(io.recvall().decode())
wait = input("Press Enter to continue.")
