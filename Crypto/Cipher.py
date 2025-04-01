from Crypto.Math import *
import hashlib


class SM4:

    __mode = None
    __file_name = None
    __IV = None

    __key_init = None

    __Sbox = [[0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05],
            [0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99],
            [0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62],
            [0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6],
            [0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8],
            [0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35],
            [0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87],
            [0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e],
            [0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1],
            [0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3],
            [0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f],
            [0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51],
            [0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8],
            [0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0],
            [0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84],
            [0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48]]

    __FK0 = 0xa3b1bac6
    __FK1 = 0x56aa3350
    __FK2 = 0x677d9197
    __FK3 = 0xb27022dc

    __CK = [0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
          0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
          0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
          0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279]

    __rk = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
          0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]

    def __move_l(self, x, k):  # 循环左移
        return ((x << k) & 0xffffffff) | (x >> (32 - k))

    def __sbox(self, x):  # s盒变换
        a = x >> 4
        b = x & 0xf
        return self.__Sbox[a][b]

    def __T0(self, x):
        a1 = (x >> 24) & 0xff
        a2 = (x >> 16) & 0xff
        a3 = (x >> 8) & 0xff
        a4 = (x >> 0) & 0xff
        tmp = (self.__sbox(a1) << 24) ^ (self.__sbox(a2) << 16) ^ (self.__sbox(a3) << 8) ^ (self.__sbox(a4) << 0)
        return tmp ^ self.__move_l(tmp, 2) ^ self.__move_l(tmp, 10) ^ self.__move_l(tmp, 18) ^ self.__move_l(tmp, 24)

    def __T1(self, x):
        x1 = (x >> 24) & 0xff
        x2 = (x >> 16) & 0xff
        x3 = (x >> 8) & 0xff
        x4 = (x >> 0) & 0xff
        tmp = (self.__sbox(x1) << 24) ^ (self.__sbox(x2) << 16) ^ (self.__sbox(x3) << 8) ^ (self.__sbox(x4) << 0)
        return tmp ^ (self.__move_l(tmp, 13)) ^ (self.__move_l(tmp, 23))  # 先x盒变换再循环移位

    def __SM4(self, key_init: int, x_init: int, op: int):
        # 生成轮密钥
        K = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        MK0 = (key_init >> 96) & 0xffffffff
        MK1 = (key_init >> 64) & 0xffffffff
        MK2 = (key_init >> 32) & 0xffffffff
        MK3 = (key_init >> 0) & 0xffffffff
        K[0] = MK0 ^ self.__FK0
        K[1] = MK1 ^ self.__FK1
        K[2] = MK2 ^ self.__FK2
        K[3] = MK3 ^ self.__FK3
        for i in range(32):
            K[i + 4] = K[i] ^ self.__T1(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ self.__CK[i])
            self.__rk[i] = K[i + 4]

        # 加密
        if op == 1:
            X = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            X[0] = (x_init >> 96) & 0xffffffff
            X[1] = (x_init >> 64) & 0xffffffff
            X[2] = (x_init >> 32) & 0xffffffff
            X[3] = (x_init >> 0) & 0xffffffff
            for i in range(32):
                X[i + 4] = X[i] ^ self.__T0(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ self.__rk[i])
            ans = '{:032x}'.format((X[35] << 96) ^ (X[34] << 64) ^ (X[33] << 32) ^ (X[32]))
            return ans
        # 解密
        elif op == 0:
            rk1 = self.__rk[::-1]
            X = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
            X[0] = (x_init >> 96) & 0xffffffff
            X[1] = (x_init >> 64) & 0xffffffff
            X[2] = (x_init >> 32) & 0xffffffff
            X[3] = (x_init >> 0) & 0xffffffff
            for i in range(32):
                X[i + 4] = X[i] ^ self.__T0(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk1[i])
            ans = '{:032x}'.format((X[35] << 96) ^ (X[34] << 64) ^ (X[33] << 32) ^ (X[32]))
            return ans


    def __init__(self, key: str, mode: str, IV=None):
        if len(key) != 32:
            print("密钥长度错误，应为128bit16进制串")
            return
        elif mode != 'ECB' and mode != 'CBC':
            print("工作模式错误，应为ECB或CBC")
            return
        else:
            if mode == "CBC" and IV is None:
                print("未输入初始向量")
                return
            elif mode == "CBC" and len(IV) != 32:
                print("初始向量长度错误，应为128bit16进制串")
                return
            else:
                self.__key_init = key
                self.mode = mode
                if mode == 'CBC':
                    self.IV = int(IV, 16)
            return

    def __padding(self, msg: list):
        # msg中每个元素为2位的str，代表一个字节，每16个字节为一组

        result = msg
        length = 16 - (len(msg) % 16)
        if length < 16:
            for i in range(length):
                result.append('{:02x}'.format(length))
        else:
            for i in range(16):
                result.append("10")
        return result

    def __ECB_encrypt(self, msg: list, key_init: int):
        # 填充
        text = self.__padding(msg)

        # 16字节为一组进行分组
        group = []
        for i in range(0, len(text), 16):
            tmp = ''.join(text[i:i + 16])
            group.append(int(tmp, 16))

        result = []
        for ele in group:
            ans = self.__SM4(key_init, ele, 1)
            result.append(ans)

        result1 = ""
        for ele in result:
            result1 = result1 + ele
        return result1

    def __ECB_decrypt(self, msg: list, key_init: int):
        # 16字节为一组进行分组
        group = []
        for i in range(0, len(msg), 16):
            tmp = ''.join(msg[i:i + 16])
            group.append(int(tmp, 16))

        result = []
        for ele in group:
            tmp = self.__SM4(key_init, ele, 0)
            result.append(tmp)

        result1 = []
        for ele in result:
            for i in range(0, 32, 2):
                result1.append(ele[i:i + 2])
        last = int(result1[-1], 16)
        ans = result1[:-last]
        ans = ''.join(ans)
        return ans

    def __CBC_encrypt(self, msg: list, key_init: int, IV: int):
        # 填充
        text = self.__padding(msg)

        # 16字节为一组进行分组
        group = []
        for i in range(0, len(text), 16):
            tmp = ''.join(text[i:i + 16])
            group.append(int(tmp, 16))

        vector = IV
        result = []
        for ele in group:
            tmp = ele ^ vector
            tmp1 = self.__SM4(key_init, tmp, 1)
            result.append(tmp1)
            vector = int(tmp1, 16)

        result1 = ""
        for ele in result:
            result1 = result1 + ele
        return result1

    def __CBC_decrypt(self, msg: list, key_init: int, IV: int):
        # 16字节为一组进行分组
        group = []
        for i in range(0, len(msg), 16):
            tmp = ''.join(msg[i:i + 16])
            group.append(int(tmp, 16))

        vector = IV
        result = []
        for ele in group:
            tmp = self.__SM4(key_init, ele, 0)
            result.append(int(tmp, 16) ^ vector)
            vector = ele

        result1 = []
        for ele in result:
            tmp = '{:032x}'.format(ele)
            for i in range(0, 32, 2):
                result1.append(tmp[i:i + 2])
        last = int(result1[-1], 16)
        ans = result1[:-last]
        ans = ''.join(ans)
        return ans

    # 普通明文加密
    def encrypt_txt(self, msg: str):
        if len(msg) % 2 != 0:
            print("明文长度错误，请以字节为单位输入")
            return
        else:
            key_init = int(self.__key_init, 16)
            msg_list = []
            for i in range(0, len(msg), 2):
                msg_list.append(msg[i:i + 2])

            if self.mode == "ECB":
                cipher = self.__ECB_encrypt(msg_list, key_init)
                return cipher
            elif self.mode == "CBC":
                cipher = self.__CBC_encrypt(msg_list, key_init, self.IV)
                return cipher

    # 普通明文解密
    def decrypt_txt(self, cipher: str):
        if len(cipher) % 2 != 0:
            print("密文长度错误，请以字节为单位输入")
            return
        else:
            key_init = int(self.__key_init, 16)
            cipher_list = []
            for i in range(0, len(cipher), 2):
                cipher_list.append(cipher[i:i + 2])

            if self.mode == "ECB":
                msg = self.__ECB_decrypt(cipher_list, key_init)
                return msg
            elif self.mode == "CBC":
                msg = self.__CBC_decrypt(cipher_list, key_init, self.IV)
                return msg

    # 文件加密
    def encrypt_file(self, file_name: str):
        if file_name is None:
            print("请输入文件名")
            return
        else:
            try:
                with open(file_name, 'rb') as file, open(file_name.replace(".txt", ".encrypt"), 'wb') as output:
                    file_bytes = file.read()
                    msg = hex(str2long(file_bytes))[2:]
                    while len(msg) < 2 * len(file_bytes):
                        msg = '0' + msg
                    key_init = int(self.__key_init, 16)
                    msg_list = []
                    for i in range(0, len(msg), 2):
                        msg_list.append(msg[i:i + 2])
                    if self.mode == "ECB":
                        cipher = self.__ECB_encrypt(msg_list, key_init)
                    elif self.mode == "CBC":
                        cipher = self.__CBC_encrypt(msg_list, key_init, self.IV)

                    for i in range(0, len(cipher), 2):
                        byte = cipher[i:i + 2]
                        output.write(bytes([int(byte, 16)]))
            except IOError as e:
                print("文件不存在")
                return

    def decrypt_file(self, file_name: str):
        if file_name is None:
            print("请输入文件名")
            return
        else:
            try:
                with open(file_name, 'rb') as file, open(file_name.replace(".encrypt", "_decrypt.txt"), 'w') as output:
                    file_bytes = file.read()
                    cipher = hex(str2long(file_bytes))[2:]
                    while len(cipher) < 2 * len(file_bytes):
                        cipher = '0' + cipher
                    key_init = int(self.__key_init, 16)
                    cipher_list = []
                    for i in range(0, len(cipher), 2):
                        cipher_list.append(cipher[i:i + 2])
                    if self.mode == "ECB":
                        msg = self.__ECB_decrypt(cipher_list, key_init)
                    elif self.mode == "CBC":
                        msg = self.__CBC_decrypt(cipher_list, key_init, self.IV)

                    outstring = ""
                    for i in range(0, len(msg), 2):
                        tmp = int(msg[i:i + 2], 16)
                        if tmp == 13:
                            output.write(outstring)
                            outstring = ""
                            continue
                        outstring = outstring + chr(tmp)
                    output.write(outstring)
            except IOError as e:
                print("文件不存在")
                return


class Hash_sha1:

    __K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]

    def __code_left_shift(self, s: str, k: int):
        """

        :param s:
        :param k:
        :return: s循环左移k位的结果
        """
        s1 = s[k:] + s[0:k]
        return s1

    def __padding(self, s: str):
        """
        :param s: 需要填充的字符串
        :return:完成位填充和长度填充的字符串s_result
        """
        # 位填充
        # 恰好满足len(s) = 448 mod 512
        s1 = s + '1'
        length = len(s1)
        while length % 512 != 448:
            s1 = s1 + '0'
            length = len(s1)

        length = len(s)
        # 长度填充
        s_result = s1 + '{:064b}'.format(length)
        return s_result

    def __group(self, s: str):
        """
        :param s:
        :return: 按512bit分组
        """
        list1 = []
        for i in range(0, len(s), 512):
            s1 = s[i:i + 512]
            list1.append(s1)
        return list1

    def __extend(self, s: str):
        """
        :param s: 512bit字符串
        :return: 80个32bit子消息
        """
        lists = []
        for i in range(16):
            lists.append(s[i * 32:(i + 1) * 32])
        for i in range(16, 80):
            tmp = '{:032b}'.format(
                int(lists[i - 3], 2) ^ int(lists[i - 8], 2) ^ int(lists[i - 14], 2) ^ int(lists[i - 16], 2))
            tmp1 = self.__code_left_shift(tmp, 1)
            lists.append(tmp1)
        return lists

    def __f1(self, B: int, C: int, D: int):
        result = (B & C) | (~B & D)
        return result

    def __f2(self, B: int, C: int, D: int):
        result = B ^ C ^ D
        return result

    def __f3(self, B: int, C: int, D: int):
        result = (B & C) | (B & D) | (C & D)
        return result

    def __f4(self, B: int, C: int, D: int):
        result = B ^ C ^ D
        return result

    def __round(self, Y: list, A: int, B: int, C: int, D: int, E: int):
        """
        :return: 80轮运算后结果CV_{q+1}
        """
        Atmp, Btmp, Ctmp, Dtmp, Etmp = A, B, C, D, E
        A_next, B_next, C_next, D_next, E_next = 0, 0, 0, 0, 0
        for i in range(80):
            if 0 <= i <= 19:
                tmp1 = self.__f1(Btmp, Ctmp, Dtmp)
                tmp2 = int(self.__code_left_shift('{:032b}'.format(Atmp), 5), 2)
                A_next = ((((Etmp + tmp1) % (2 ** 32) + tmp2) % (2 ** 32) + int(Y[i], 2)) % (2 ** 32) + self.__K[0]) % (
                            2 ** 32)
            elif 20 <= i <= 39:
                tmp1 = self.__f2(Btmp, Ctmp, Dtmp)
                tmp2 = int(self.__code_left_shift('{:032b}'.format(Atmp), 5), 2)
                A_next = ((((Etmp + tmp1) % (2 ** 32) + tmp2) % (2 ** 32) + int(Y[i], 2)) % (2 ** 32) + self.__K[1]) % (
                            2 ** 32)
            elif 40 <= i <= 59:
                tmp1 = self.__f3(Btmp, Ctmp, Dtmp)
                tmp2 = int(self.__code_left_shift('{:032b}'.format(Atmp), 5), 2)
                A_next = ((((Etmp + tmp1) % (2 ** 32) + tmp2) % (2 ** 32) + int(Y[i], 2)) % (2 ** 32) + self.__K[2]) % (
                            2 ** 32)
            elif 60 <= i <= 79:
                tmp1 = self.__f4(Btmp, Ctmp, Dtmp)
                tmp2 = int(self.__code_left_shift('{:032b}'.format(Atmp), 5), 2)
                A_next = ((((Etmp + tmp1) % (2 ** 32) + tmp2) % (2 ** 32) + int(Y[i], 2)) % (2 ** 32) + self.__K[3]) % (
                            2 ** 32)

            B_next = Atmp
            C_next = int(self.__code_left_shift('{:032b}'.format(Btmp), 30), 2)
            D_next = Ctmp
            E_next = Dtmp

            Atmp, Btmp, Ctmp, Dtmp, Etmp = A_next, B_next, C_next, D_next, E_next

        A_result = (Atmp + A) % (2 ** 32)
        B_result = (Btmp + B) % (2 ** 32)
        C_result = (Ctmp + C) % (2 ** 32)
        D_result = (Dtmp + D) % (2 ** 32)
        E_result = (Etmp + E) % (2 ** 32)

        return A_result, B_result, C_result, D_result, E_result

    def __F(self, lists: list):
        """
        :param lists:
        :param round:
        :return:
        """
        A, B, C, D, E = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
        for i in range(len(lists)):
            # 第1次
            if i == 0:
                Y = self.__extend(lists[0])
                Atmp, Btmp, Ctmp, Dtmp, Etmp = self.__round(Y, A, B, C, D, E)
                # s1 = '{:032b}'.format(A) + '{:032b}'.format(B) + '{:032b}'.format(C) + '{:032b}'.format(D) + '{:032b}'.format(E)
                # s2 = '{:032b}'.format(Atmp) + '{:032b}'.format(Btmp) + '{:032b}'.format(Ctmp) + '{:032b}'.format(Dtmp) + '{:032b}'.format(Etmp)
                # stmp = '{:0160b}'.format(int(s1, 2) ^ int(s2, 2))
                A, B, C, D, E = Atmp, Btmp, Ctmp, Dtmp, Etmp
            else:
                Y = self.__extend(lists[i])
                Atmp, Btmp, Ctmp, Dtmp, Etmp = self.__round(Y, A, B, C, D, E)
                # s1 = '{:032b}'.format(A) + '{:032b}'.format(B) + '{:032b}'.format(C) + '{:032b}'.format(D) + '{:032b}'.format(E)
                # s2 = '{:032b}'.format(Atmp) + '{:032b}'.format(Btmp) + '{:032b}'.format(Ctmp) + '{:032b}'.format(Dtmp) + '{:032b}'.format(Etmp)
                # stmp = '{:0160b}'.format(int(s1, 2) ^ int(s2, 2))
                A, B, C, D, E = Atmp, Btmp, Ctmp, Dtmp, Etmp

        result = '{:08x}'.format(A) + '{:08x}'.format(B) + '{:08x}'.format(C) + '{:08x}'.format(D) + '{:08x}'.format(E)
        return result

    def __sha1(self, s):
        """

        :param s: 输入字符串
        :return:
        """
        if len(s) > 2 ** 64:
            return False
        s1 = ""
        for ele in s:
            s1 = s1 + '{:08b}'.format(ele)
        # 位填充&长度填充
        s2 = self.__padding(s1)
        # correct

        # 分组
        lists = self.__group(s2)
        # print(lists)
        # correct

        result = self.__F(lists)
        return result

    def sha1_txt(self, msg: str):
        if msg is None:
            print("请输入明文内容")
            return
        else:
            s = self.__sha1(msg.encode(encoding='utf-8'))
            return s

    def sha1_file(self, file_name: str):
        if file_name is None:
            print("请输入文件名")
            return
        else:
            try:
                with open(file_name, 'rb') as file:
                    file_bytes = file.read()
                    msg = file_bytes.decode(encoding='utf-8')
                    s = self.__sha1(msg.encode(encoding='utf-8'))
                    return s
            except IOError as e:
                print("文件不存在")
                return

