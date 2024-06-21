import argparse
import math
import pefile

from prettytable import PrettyTable

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file','-f', required = True, help = "target file")
    
    return parser.parse_args()

def shannon_entropy(data):
    # 256 different possible values
    possible = dict(((chr(x), 0) for x in range(0, 256)))

    for byte in data:
        possible[chr(byte)] +=1

    data_len = len(data)
    entropy = 0.0

    # compute
    for i in possible:
        if possible[i] == 0:
            continue

        p = float(possible[i] / data_len)
        entropy -= p * math.log(p, 2)
    return entropy

def calculate_section_entropy(path):
    pe = pefile.PE(path)

    table = PrettyTable()
    table.field_names = ["Section", "Virt Addr", "Virt Size", "Raw Size", "Entropy"]
    table.align = "r"
    table.align["Section"] = "l"

    for section in pe.sections:
        tmp = [
            section.Name.decode('utf-8'), 
            hex(section.VirtualAddress), 
            hex(section.Misc_VirtualSize), 
            hex(section.SizeOfRawData),
            f"{shannon_entropy(section.get_data()):.4f}"
        ]
        table.add_row(tmp)

    print(table.get_string())


def main():
    args = parse_arguments()
    target_file = args.file

    print(args.file)

    with open(target_file, 'rb') as f:
        calculate_section_entropy(target_file)
    
    with open(target_file, 'rb') as f:
        data = f.read()
        print(f"Overall Entropy: {shannon_entropy(data):.4f}")


if __name__ == "__main__":
    main()