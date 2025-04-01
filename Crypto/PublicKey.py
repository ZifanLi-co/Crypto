from Crypto.Math import *
from random import *
from Crypto.Cipher import Hash_sha1

class RSA:

    class generate:

        __length = None
        __public_pem = None
        __n = None

        __private_pem = None
        __p = 0
        __q = 0
        __phi = None

        def __init__(self, length: int):
            if length < 1024:
                print("安全参数较小，至少为1024")
                return
            else:
                self.length = length
                while self.__p == self.__q:
                    self.__p = generate_prime_number(length)
                    self.__q = generate_prime_number(length)

                self.__phi = (self.__p - 1) * (self.__q - 1)
                self.__n = self.__p * self.__q
                return

        def exportKey(self):
            if self.__n is None:
                print("请先创建RSA密钥对象")
                return

            while True:
                private_pem = randint(2, self.__phi)
                if gcd(private_pem, self.__phi) == 1:
                    self.__private_pem = private_pem
                    break
            return self.__private_pem

        def publicKey(self):
            if self.__private_pem is None:
                print("请先生成私钥")
                return

            self.__public_pem = inverse(self.__private_pem, self.__phi)
            return self.__public_pem, self.__n

    class Encrypt:

        __public_e = None
        __public_n = None

        def keyimport(self, public_e: int, public_n: int):
            self.__public_e = public_e
            self.__public_n = public_n
            return

        def encrypt(self, msg: str):
            if self.__public_n is None:
                print("请先载入公钥")
                return
            # 将明文类型转换为int
            m = str2long(bytes(msg, encoding='utf-8'))

            if m > self.__public_n:
                print("明文较大，请增大安全参数或减少明文长度")
                return

            cipher = fastmod(m, self.__public_e, self.__public_n)
            return cipher

    class Decrypt:

        __public_n = None
        __private_d = None

        def keyimport(self, private_d: int, public_n: int):
            self.__private_d = private_d
            self.__public_n = public_n
            return

        def decrypt(self, cipher: int):
            msg = fastmod(cipher, self.__private_d, self.__public_n)
            m = long2str(msg).decode()
            return m


class ElGamal:

    class generate:

        __length = None
        __public_y = None
        __public_p = None
        __public_g = None

        __private_x = None

        def __init__(self, length: int):
            if length < 1024:
                print("安全参数较小，至少为1024")
                return
            else:
                self.__length = length
                self.__public_p = generate_prime_number(length)
                while True:
                    g = randint(2, self.__public_p - 1)
                    if fastmod(g, self.__public_p - 1, self.__public_p) == 1:
                        break
                self.__public_g = g
                return

        def exportKey(self):
            if self.__public_p is None:
                print("请先创建ElGamal密钥对象")
                return
            else:
                self.__private_x = randint(2, self.__public_p - 2)
                return self.__private_x

        def publicKey(self):
            if self.__private_x is None:
                print("请先生成私钥")
                return
            else:
                self.__public_y = fastmod(self.__public_g, self.__private_x, self.__public_p)
                return self.__public_y, self.__public_g, self.__public_p

    class Sign:

        __random_k = None

        __public_y = None
        __public_p = None
        __public_g = None

        __private_x = None

        def keyimport(self, y: int, p: int, g: int, x: int):
            self.__public_y = y
            self.__public_p = p
            self.__public_g = g
            self.__private_x = x
            return

        def sign(self, msg: str):
            if self.__public_p is None:
                print("请先载入公钥")
                return
            else:
                # 创建sha1对象
                sha1 = Hash_sha1()
                m = int(sha1.sha1_txt(msg), 16)

                while True:
                    k = randint(2, self.__public_p - 2)
                    if gcd(k, self.__public_p - 1) == 1:
                        self.__random_k = k
                        break

                S1 = fastmod(self.__public_g, self.__random_k, self.__public_p)
                S2 = (inverse(self.__random_k, self.__public_p - 1) * (m - self.__private_x * S1)) % (self.__public_p - 1)
                return S1, S2

    class Vrfy:

        __public_y = None
        __public_p = None
        __public_g = None

        def keyimport(self, y: int, p: int, g: int):
            self.__public_y = y
            self.__public_p = p
            self.__public_g = g
            return

        def vrfy(self, msg: str, S1: int, S2: int):
            if self.__public_p is None:
                print("请先载入公钥")
                return
            else:
                # 创建sha1对象
                sha1 = Hash_sha1()
                m = int(sha1.sha1_txt(msg), 16)

                V1 = fastmod(self.__public_g, m, self.__public_p)
                V2 = (fastmod(self.__public_y, S1, self.__public_p) * fastmod(S1, S2, self.__public_p)) % self.__public_p

                return V1 == V2


