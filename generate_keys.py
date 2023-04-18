
import subprocess
import os
import sys
import re

sys.set_int_max_str_digits(int(10e8))

raw_hex_to_int = lambda x: int(re.sub(r"[ :\n]", "", x), 16)
find_and_extract_hex_int = lambda regex, data: raw_hex_to_int(re.search(regex, data).groups()[0])

def gen_keys(name):
    gen = 'openssl genrsa -out ./{} 2048'
    output = 'openssl rsa -in ./{} -text -noout'
    with open(os.devnull, 'wb') as devnull:
        cmd = gen.format(name)
        res = subprocess.check_call(cmd, stdout=devnull, stderr=subprocess.STDOUT, shell=True)
        assert(res == 0)
        cmd = output.format(name)
        res = subprocess.check_call(cmd, stdout=open("./tmp", 'w+'), stderr=subprocess.STDOUT, shell=True)
        assert(res == 0)

    with open("tmp", 'r') as f:
        data = f.read()

    out = re.search(r'publicExponent:\W(\d*)', data)
    public_key = int(out.groups()[0])

    private_key = find_and_extract_hex_int(r"privateExponent:\n([\d:abcdef\n ]*)prime1", data)
    p = find_and_extract_hex_int(r"prime1:\n([\d:abcdef\n ]*)prime2", data)
    q = find_and_extract_hex_int(r"prime2:\n([\d:abcdef\n ]*)exponent1", data)

    n = p * q

    # Store these keys in an appropriate secret file
    with open("./my_secrets/{}.py".format(name), "w+") as f:
        f.write("PUBLIC_KEY = ")
        f.write(str(public_key))
        f.write("\nPRIVATE_KEY = ")
        f.write(str(private_key))
        f.write("\nP = ")
        f.write(str(p))
        f.write("\nQ = ")
        f.write(str(q))
        f.write("\n")

    with open("./my_secrets/{}_public.py".format(name), "w+") as f:
        f.write("PUBLIC_KEY = ")
        f.write(str(public_key))
        f.write("\nN = ")
        f.write(str(n))
        f.write("\n")

    # Clean up files
    os.remove(name)
    os.remove("./tmp")

    print("Generated keys for: {}".format(name))

# Make the keys
gen_keys("server")
gen_keys("client")
