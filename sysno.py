import json
import os
import pathlib
import re
import shlex
import subprocess
import sys

from collections import OrderedDict
from operator import itemgetter


CONFIG = {
    "syscall_header_file": "/usr/include/bits/syscall.h",
    "cache_file_64bit": "{}/.cache/syscall_number/64bit.json".format(
        os.environ["HOME"]
    ),
}


BITNESS_32 = "32"
BITNESS_64 = "64"


def read_file_content(file_path):
    try:
        return pathlib.Path(file_path).read_text()
    except (FileNotFoundError, UnicodeDecodeError):
        raise RuntimeError("Error(s) reading from file {}".format(file_path))


def write_file_content(file_path, data):
    try:
        return pathlib.Path(file_path).write_text(data)
    except (FileNotFoundError, UnicodeDecodeError):
        raise RuntimeError("Error(s) writing to file {}".format(file_path))


def parse_syscall_names():
    syscall_names = []

    syscall_name_regex = re.compile(r"^.+SYS_(?P<syscall_name>[^ ]+)")

    try:
        content = read_file_content(CONFIG["syscall_header_file"])
    except RuntimeError as error:
        raise error

    for line in content.split("\n"):
        match = syscall_name_regex.match(line)

        if match:
            syscall_names.append(match.group("syscall_name"))

    return syscall_names


def check_program(program_name):
    try:
        output = subprocess.check_output(
            "which {}".format(program_name).split(), shell=False
        )
    except OSError:
        output = ""

    return output != ""


def check_sane_integer(syscall_number):
    try:
        syscall_integer = int(syscall_number)

        if not 0 <= syscall_integer <= 999:
            return False

    except ValueError:
        return False

    return True


def get_syscall_number(syscall_name, bitness):
    if bitness == BITNESS_32:
        cflags = "-m32"
    else:
        cflags = ""

    gcc_process = subprocess.Popen(
        shlex.split("gcc {} -E -".format(cflags)),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    gcc_process.stdin.write(
        b"#include <sys/syscall.h>\nSYS_%s" % syscall_name.encode()
    )
    stdout, _ = gcc_process.communicate()

    syscall_number_string = stdout.split(b"\n")[-2].decode()

    if not check_sane_integer(syscall_number_string):
        return -1

    return int(syscall_number_string)


def generate_syscalls(syscall_names, bitness):
    syscalls = {}

    for syscall_name in syscall_names:
        syscalls[syscall_name] = get_syscall_number(syscall_name, bitness)

    return OrderedDict(sorted(syscalls.items(), key=itemgetter(1)))


def cache_files_exist():
    return pathlib.Path(CONFIG["cache_file_64bit"]).exists()


def check_cache():
    if cache_files_exist():
        syscalls_32bit = json.loads(
            read_file_content(CONFIG["cache_file_32bit"])
        )
        syscalls_64bit = json.loads(
            read_file_content(CONFIG["cache_file_64bit"])
        )
    else:
        syscall_names = parse_syscall_names()
        syscalls_32bit = generate_syscalls(syscall_names, BITNESS_32)
        syscalls_64bit = generate_syscalls(syscall_names, BITNESS_64)
        write_file_content(
            CONFIG["cache_file_32bit"], json.dumps(syscalls_32bit)
        )
        write_file_content(
            CONFIG["cache_file_64bit"], json.dumps(syscalls_64bit)
        )

    return syscalls_32bit, syscalls_64bit


def print_all_syscalls(syscalls):
    for syscall_name, syscall_number in syscalls.items():
        if syscall_number == -1:  # filter out n/a syscall numbers
            continue

        print("{0:3} (0x{0:x}): {1}".format(syscall_number, syscall_name))


def print_single_syscall(syscall_name, syscalls, quiet):
    if quiet:
        print(syscalls[syscall_name])
    else:
        print(
            "The syscall number for {0} is: {1} (0x{1:x})".format(
                syscall_name,
                syscalls[syscall_name],
            )
        )


def get_and_print_syscall_name(syscall_number, syscalls, quiet):
    for name, number in syscalls.items():
        if number == syscall_number:
            syscall_name = name
            break

    if quiet:
        print(syscall_name)
    else:
        print(
            "The syscall name for syscall number {0} (0x{0:x}) is: {1}".format(
                syscall_number, syscall_name
            )
        )

    return syscall_name


def check_cache_directory():
    directory = "{}/.cache/syscall_number".format(os.environ["HOME"])

    if not pathlib.Path(directory).exists():
        os.mkdir(directory)


def check_syscall_header_file():
    if not pathlib.Path(CONFIG["syscall_header_file"]).exists():
        raise RuntimeError(
            "Install gcc with 32bit support: https://github.com/martinclauss/syscall_number#gcc-with-32bit-support"
        )


def check_cache():
    if cache_files_exist():
        syscalls_64bit = json.loads(
            read_file_content(CONFIG["cache_file_64bit"])
        )
    else:
        syscall_names = parse_syscall_names()
        syscalls_64bit = generate_syscalls(syscall_names, BITNESS_64)
        write_file_content(
            CONFIG["cache_file_64bit"], json.dumps(syscalls_64bit)
        )

    return syscalls_64bit


def sysno_to_name(sysno: int) -> str:
    check_cache_directory()
    check_syscall_header_file()

    syscalls = check_cache()

    if sysno not in syscalls.values():
        raise ValueError("The syscall number you provided is not available!")

    for name, number in syscalls.items():
        if number == sysno:
            return name

    raise ValueError("The syscall number you provided is not available!")


if __name__ == "__main__":
    print(sysno_to_name(60))
