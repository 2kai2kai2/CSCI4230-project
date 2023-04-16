from math import lcm

def validate(pkg):
    totient = lcm(pkg.P - 1, pkg.Q - 1)
    validate = (pkg.PUBLIC_KEY * pkg.PRIVATE_KEY) % totient
    assert(validate == 1)

if __name__ == "__main__":
    import client
    import server
    validate(client)
    validate(server)
