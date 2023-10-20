#! /usr/bin/env python3

import sys
import re

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage:", sys.argv[0], "<process PID>", file=sys.stderr)
        exit(1)

    pid = sys.argv[1]

    map_file = f"/proc/{pid}/maps"
    mem_file = f"/proc/{pid}/mem"

    with open(map_file, "r") as map_f, open(mem_file, "rb", 0) as mem_f:
        for line in map_f.readlines():  # for each mapped region
            m = re.match(
                r"^([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([rwxp-]+) .*?(|[\/\[].*?)$",
                line,
            )
            if m.group(4):
                name = m.group(4).replace("/", "_")
            else:
                name = "anonymous"
            perms = m.group(3)
            if "r" in perms:  # readable region
                start = int(m.group(1), 16)
                end = int(m.group(2), 16)
                mem_f.seek(start)  # seek to region start
                print(f"Dumping: {hex(start)} - {hex(end)} {perms} {name}")
                try:
                    chunk = mem_f.read(end - start)  # read region contents
                    with open(
                        f"{pid}::{hex(start)}-{hex(end)}::{perms}::{name}.bin",
                        "wb",
                    ) as out_f:
                        out_f.write(chunk)
                except OSError as E:
                    print(
                        hex(start),
                        "-",
                        hex(end),
                        E,
                        file=sys.stderr,
                    )
                    continue
    print(f"Memory dumps saved")
