import sys

sys.path.insert(0, ".")

import gdb

from sysno import sysno_to_name


class SyscallBP(gdb.Breakpoint):
    def stop(self):
        args = []
        arg1 = "arg1"
        arg2 = "arg2"
        arg3 = "arg3"
        arg4 = "arg4"
        arg5 = "arg5"
        val1 = None
        val2 = None
        val3 = None
        val4 = None
        val5 = None

        rax = gdb.parse_and_eval("$rax")

        setattr(self.post, "rax", rax)

        if rax in (0, 1):
            # read or write
            arg1 = "fd"
            arg2 = "buf"
            arg3 = "n"
        elif rax == 2:
            # open
            arg1 = "name"
            val1 = gdb.execute('x/s $rdi', to_string=True)
        elif rax == 60:
            # exit
            gdb.execute("bt")
            return True
        elif rax == 0x9d:
            # prctl
            print("[+] replace prctl -> close(-1)")
            gdb.execute("set $rax = 3")
            gdb.execute("set $rdi = -1")

        args.append(f"{arg1}={val1 if val1 else gdb.parse_and_eval('$rdi')}")
        args.append(f"{arg2}={val2 if val2 else gdb.parse_and_eval('$rsi')}")
        args.append(f"{arg3}={val3 if val3 else gdb.parse_and_eval('$rdx')}")
        args.append(f"{arg4}={val4 if val4 else gdb.parse_and_eval('$r10')}")
        args.append(f"{arg5}={val5 if val5 else gdb.parse_and_eval('$r8')}")

        self.post.enabled = True
        setattr(self.post, "args", args)

        return False


class PostSyscallBP(gdb.Breakpoint):
    def stop(self):
        name = sysno_to_name(self.rax)
        ret = gdb.parse_and_eval("$rax")
        print(f"SYS_{name}({','.join(self.args)}) -> {ret}")

        if name == "read":
            print("[+] remove TracerPid")
            buf = gdb.parse_and_eval("$rsi")
            replace_string = "TracerPid:\t0"
            gdb.execute(
                "set { "
                + f"char [{len(replace_string) + 1}] "
                + "}"
                + f' {buf} = "{replace_string}"'
            )
            gdb.execute(
                f"set *(char*){buf + 0xc} = 0xa"
            )
        elif name == "prctl":
            print("[+] fake success")
            gdb.execute("set $rax = 0")
            pass

        self.enabled = False
        return False


def hook_syscalls():
    # addresses of all syscall insns
    # [x[0] for x in [[i[1] for i in f.instructions if str(i[0][0]) == 'syscall'] for f in bv.functions] if x]
    syscall_addr = [
        2106445,
        2106493,
        2106544,
        2106580,
        2106609,
        2106679,
        2106784,
        2106837,
        2106889,
        2106926,
        2106970,
        2107054,
        2107114,
        2107181,
        2107226,
        2107274,
    ]
    for a in syscall_addr:
        pre = SyscallBP(f"*{a}")
        post = PostSyscallBP(f"*{a+2}")
        post.enabled = False
        setattr(pre, "post", post)

class SkipEnv(gdb.Breakpoint):
    def stop(self):
        # bypass checking of env vars
        gdb.execute("set $rip = 0x2002ba")
        gdb.execute("detach")

def main():
    hook_syscalls()

    gdb.execute("set env LD_PRELOAD = ./frida-gadget-16.1.4-linux-x86_64.so")
    #gdb.execute("set env LD_PRELOAD = ./library.so")

    SkipEnv("*0x2002b5")

    gdb.execute("r < ./flag.txt")

    """
    # hit BP, bypass adbg check
    while True:
        gdb.execute("si")
        gdb.execute("set $rax = *(unsigned long*)0x203970")
        gdb.execute("c")
    """


main()
