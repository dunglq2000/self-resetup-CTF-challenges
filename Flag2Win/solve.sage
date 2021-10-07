from pwn import *
from tqdm import tqdm
from parse import parse
from Crypto.Util.number import bytes_to_long
from hashlib import sha256

from sage.matrix.matrix2 import Matrix

def resultant(f1, f2, var):
	return Matrix.determinant(f1.sylvester_matrix(f2, var))

p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0
b = 7
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

E = EllipticCurve(GF(p), [a, b])
G = E(G)

def get_sig():
	conn.sendlineafter(b'choice? ', b'1')
	conn.recvline()
	x = list(parse('x = {:d}\n', conn.recvline().decode()))[0]
	s = list(parse('s = {:d}\n', conn.recvline().decode()))[0]
	return int(x), int(s)

def recover_d(x1, s1, x2, s2):
	l = 26
	ln = 2
	P = PolynomialRing(Zmod(n), [f'r{j}{i}' for j in range(ln) for i in range(l)] + ['d'])
	R, d = P.gens()[:l*ln], P.gens()[-1]
	k1 = sum(48*2^(8*i) for i in range(l)) + sum(R[i]*2^(8*i) for i in range(l))
	k2 = sum(48*2^(8*i) for i in range(l)) + sum(R[i+l]*2^(8*i) for i in range(l))
	f1 = s1*k1 - z - x1*d
	f2 = s2*k2 - z - x2*d
	f = resultant(f1, f2, d)
	M = matrix.column(ZZ, vector([int(c) for c,_ in f]))
	M = M.augment(matrix.identity(l*ln+1))
	M = M.stack(vector([n] + [0]*(l*ln+1)))
	M = M.dense_matrix()
	M = M.BKZ()
	r_subs = {R[i]: abs(M[0][i+1]) for i in range(l*ln)}
	k1 = k1.subs(r_subs)
	k2 = k2.subs(r_subs)
	print(hex(k1))
	print(hex(k2))
	d = (s1 * k1 - z) * inverse_mod(x1, n) % n
	return d

conn = remote('localhost', 35719)

z = bytes_to_long(sha256(b'Baba').digest())
x1, s1 = get_sig()
x2, s2 = get_sig()

d = recover_d(x1, s1, x2, s2)
my_z = bytes_to_long(sha256(b'Flag').digest())
k = 1337
x, _ = (k*G).xy()
s = inverse_mod(k, n) * (my_z + int(x) * d) % n

conn.sendlineafter(b'choice? ', b'2')
conn.sendlineafter(b'know? ', b'Flag')
conn.sendlineafter(b'x? ', str(x).encode())
conn.sendlineafter(b's? ', str(s).encode())
print(conn.recvline().decode())
