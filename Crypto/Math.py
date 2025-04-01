import math
from random import randint, getrandbits


def gcd(a, b):
    """
    :param a:
    :param b:
    :return:a,b的最大公约数
    """
    while a % b != 0:
        r = a % b
        a = b
        b = r
    return b


def extended_euclid(a: int, b: int):
    """

    :param a:
    :param b:
    :return: 返回a和b的最大公因数r1，且r1 = (s1 * a) + (t1 * b)
    """
    r1, s1, t1 = a, 1, 0
    r2, s2, t2 = b, 0, 1
    while r2 != 0:
        q = r1 // r2
        r0, s0, t0 = r1 - (q * r2), s1 - (q * s2), t1 - (q * t2)
        r1, s1, t1 = r2, s2, t2
        r2, s2, t2 = r0, s0, t0
    return r1, s1, t1


def inverse(e, m):
    """
    :param e:
    :param m:
    :return: e模m的逆元d,即(e * d) = 1 (mod m)
    """
    tem = gcd(e, m)
    if (tem == 1) and (m > 1):
        r, d, k = extended_euclid(e, m)
        d = (d + m) % m
        return d
    else:
        print(f"Error in inverse!")
        return False


def fastmod(b, n, m):
    """
    :param b:
    :param n:
    :param m:
    :return:
    """
    s = ""
    if n < 0:
        n0 = -1 * n
    else:
        n0 = n
    list = []
    while n0 > 0:
        r = n0 % 2
        s = s + str(r)
        n0 = n0 // 2
    i = 0
    length = len(s)
    ans = 1
    while i < length:
        if i == 0:
            list.append(b)
        else:
            list.append(pow(list[i - 1], 2, m))
        i = i + 1
    i = 0
    for ele in s:
        if ele == "1":
            ans = (ans * list[i]) % m
        i = i + 1

    if n < 0:
        ans = inverse(ans, m)

    return ans


def isPrime(n, k = 10):
    """

    :param n:
    :return: 如果n为素数返回True,否则返回False
    通过米勒-拉宾素性检验判断n是否为素数，检测因子g在(1, n - 1)范围随机生成，若10次均未通过，则为素数
    """
    if n <= 1:
        return False
    if n <= 3:
        return True

    # 检查偶数
    if n % 2 == 0:
        return False

    # 将n-1表示为2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # 进行k次Miller-Rabin测试
    for _ in range(k):
        a = randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime_number(length):
    """

    :param length:
    :return: 返回长度为length的随机素数
    """
    while True:
        # 生成一个长度为 length 的随机奇数
        num = getrandbits(length)
        num |= (1 << length - 1) | 1
        # 此步骤确保数字最高位和最低位均为1
        # 检查 num 是否为质数
        if isPrime(num):
            return num


def str2long(s: bytes):
    ans = int.from_bytes(s, byteorder='big')
    return ans


def long2str(s: int):
    size = math.ceil(len(bin(s)[2:]) / 8)
    ans = s.to_bytes(size, byteorder='big')
    return ans


if __name__ == "__main__":
    s = 66051
    print(long2str(s, 6))
