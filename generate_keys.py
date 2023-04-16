
import subprocess
import os
import sys
from base64 import b64decode

sys.set_int_max_str_digits(int(10e8))

def gen_keys(name):
    command = 'ssh-keygen -t rsa -b 2048 -f ./{:} -N \"\"'
    # Run ssh-keygen to generate the keys
    cmd = command.format(name)
    with open(os.devnull, 'wb') as devnull:
        res = subprocess.check_call(cmd, stdout=devnull, stderr=subprocess.STDOUT, shell=True)
    assert(res == 0)

    # Read in the base64 encoded numbers
    with open(name) as f:
        data = f.read()
    data = data.split("\n")
    data = data[1:-2] # Strip out the first line and the last line (plus the extra \n)
    data = "".join(data)
    private_key = int.from_bytes(b64decode(data), 'big')

    with open("{}.pub".format(name)) as f:
        data = f.read()
    data = data.split(" ")
    data = data[1:-1] # Strip out the first line and the last line (plus the extra \n)
    data = "".join(data)
    public_key = int.from_bytes(b64decode(data), 'big')

    # Store these keys in an appropriate secret file
    with open("./my_secrets/{}.py".format(name), "w+") as f:
        f.write("PRIVATE_KEY = ")
        f.write(str(private_key))
        f.write("\n")

    with open("./my_secrets/{}_public.py".format(name), "w+") as f:
        f.write("PUBLIC_KEY = ")
        f.write(str(public_key))
        f.write("\n")

    # Clean up files
    os.remove(name)
    os.remove("{}.pub".format(name))

    print("Generated keys for: {}".format(name))

# Make the keys
gen_keys("server")
gen_keys("client")
