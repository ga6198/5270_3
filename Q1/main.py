#assumes v is bigger
"""
def gcd(u, v):
    if u == 0:
        return v;

    quotient = v//u;
    remainder = v % u;
    
    return gcd(remainder, u)
"""

def gcd(u, v):
    temp = 0

    a1 = 0
    a2 = 1
    b1 = 1
    b2 = 0
    
    while u != 0:
        temp = u #save value of u

        quotient = v//u;
        remainder = v % u;

        u = remainder
        v = temp; #give v u's old value

        a3 = a1 - (quotient*a2)
        b3 = b1 - (quotient*b2)

        #print out the current iteration of values
        #print(u, v, quotient, remainder, a1, a2, a3, b1, b2, b3)

        #update the values of a1 and a2, b1 and b2 for next iteration/row
        a1 = a2
        a2 = a3
        b1 = b2
        b2 = b3

    #print(a1, b1)

    return a1, b1, v

if __name__ == "__main__":
    #print(gcd(28, 161))
    #print(gcd(20, 30))
    #print(gcd(15, 35))

    u=612898
    v=765051

    a, b, c = gcd(u, v)
    print("a:", a)
    print("b:", b)
    print("c (gcd):", c)

    print(a, "*", u, "+", b, "*", v, "=", a*u+b*v)
