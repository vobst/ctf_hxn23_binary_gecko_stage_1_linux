import angr
import cle
from cle.backends.binja import BinjaBin

# use binja as default loader throws exception
b = BinjaBin(
    "8251_anonymous_dump_0x800000000.bin",
    open("8251_anonymous_dump_0x800000000.bin", "rb"),
)

l = cle.Loader(b)

p = angr.Project(l)

# start of heavy checks
s = p.factory.blank_state(addr=0x1351)

# [rbp - 8] is ptr to our data +5
s.regs.rbp = 0x10000
s.mem[s.regs.rbp - 8].uint64_t = 0x11000
s.mem[0x11000].uint8_t = 0x44

# flag should be printable ascii
for i in range(1, 0x38):
    b = s.memory.load(0x11000 + i, 1)
    s.add_constraints(b < 0x7f, b >= 0x20)

sm = p.factory.simulation_manager(s)

sm.explore(find = 0x1fb4, avoid=[0x1fc7])
ss = sm.found[0]

flag = ["F", "L", "A", "G", "{"]
for i in range(0x64):
    c = chr(ss.mem[0x11000 + i].uint8_t.concrete)
    flag.append(c)
print("".join(flag)) # FLAG{DC_I_0h1nk_y0u_mad3_4_B1G_mil3sUPn3_R3V3@S3d_K33p_G01ng}
