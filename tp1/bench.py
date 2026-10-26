"""Etape 1 : mesurer Argon2id pour viser ~0,5 s. Usage : python bench.py"""
import os, time
import coffre

sel = os.urandom(16)
for t, m in [(1, 32*1024), (2, 64*1024), (3, 64*1024), (3, 128*1024), (4, 128*1024)]:
    d = time.perf_counter()
    coffre.cle_maitresse("test", sel, t, m, 4)
    print(f"t={t} m={m//1024:>4} Mio p=4 -> {time.perf_counter()-d:.3f} s")
