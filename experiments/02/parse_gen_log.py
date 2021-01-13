#!/usr/bin/env python3

def write_parsed_line(lines, fd):
    to_write = ""
    dic = {}
    for line in lines:
        if line.startswith("S-"):
            to_write += "Symex:\n"
            to_write += line.split("\t", 1)[1]
            to_write += "\n"
        elif line.startswith("T-"):
            to_write += "Math:\n"
            to_write += line.split("\t", 1)[1]
            to_write += "\n"
        elif line.startswith("H-"):
            to_write += "Translated:\n"
            to_write += line.split("\t", 2)[2]
            to_write += "\n"
            score = line.split()[1]
            to_write += "\nScore: %s\n" % score
            to_write += "\n===============\n"
            idx = int(line.split()[0].split("-")[1])
            dic[idx] = "%s\n" % idx
            dic[idx] += to_write
            to_write = ""

    for idx in range(len(dic)):
        fd.write(dic[idx])


def main():
    gen_log = "gen.log"
    with open(gen_log, "r") as fd:
        lines = fd.readlines()

    out = "parse_result.log"

    with open(out, "w") as fd:
        write_parsed_line(lines, fd)


if __name__ == '__main__':
    main()

