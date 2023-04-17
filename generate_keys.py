
import subprocess
import os
import sys
#from base64 import b64decode
#from cryptography import x509
#from cryptography.hazmat.backends import default_backend
import re

sys.set_int_max_str_digits(int(10e8))

raw_hex_to_int = lambda x: int(re.sub(r"[ :\n]", "", x), 16)
find_and_extract_hex_int = lambda regex, data: raw_hex_to_int(re.search(regex, data).groups()[0])

def gen_keys(name):
    # gen = 'ssh-keygen -t rsa -b 2048 -f ./{:} -N \"\"'
    gen = 'openssl genrsa -out ./{} 2048'
    output = 'openssl rsa -in ./{} -text -noout'
    # Run ssh-keygen to generate the keys
    with open(os.devnull, 'wb') as devnull:
        cmd = gen.format(name)
        res = subprocess.check_call(cmd, stdout=devnull, stderr=subprocess.STDOUT, shell=True)
        assert(res == 0)
        cmd = output.format(name)
        res = subprocess.check_call(cmd, stdout=open("./tmp", 'w+'), stderr=subprocess.STDOUT, shell=True)
        assert(res == 0)

    # # Read in the base64 encoded numbers
    with open("tmp", 'r') as f:
        data = f.read()
    # data = data.split("\n")
    # data = data[1:-2] # Strip out the first line and the last line (plus the extra \n)
    # data = "".join(data)
    # private_key = int.from_bytes(b64decode(data), 'big')

    # # cert = x509.load_pem_x509_certificate(data, default_backend())
    # # cert.serial_number
    # # print(cert)

    # with open("{}.pub".format(name)) as f:
    #     data = f.read()
    # data = data.split(" ")
    # data = data[1:-1] # Strip out the first line and the last line (plus the extra \n)
    # data = "".join(data)
    # public_key = int.from_bytes(b64decode(data), 'big')

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
