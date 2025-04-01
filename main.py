from Crypto.Math import *
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Cipher import SM4, Hash_sha1
if __name__ == '__main__':
    # RSA公钥加解密
    # 创建密钥
    rsa = RSA.generate(1024)
    # 返回私钥
    private_pem = rsa.exportKey()
    # 返回公钥
    public_pem, n = rsa.publicKey()
    msg = "data"
    print(f"明文：{msg}")
    
    # 加密
    # 创建加密对象
    rsa_encrypt = RSA.Encrypt()
    # 载入公钥并加密
    rsa_encrypt.keyimport(public_pem, n)
    cipher = rsa_encrypt.encrypt(msg)
    print(f"密文：{cipher}")
    
    # 解密
    # 创建解密对象
    rsa_decrypt = RSA.Decrypt()
    # 载入私钥并解密
    rsa_decrypt.keyimport(private_pem, n)
    m = rsa_decrypt.decrypt(cipher)
    print(f"解密结果：{m}")


    # SM4普通明文加解密，ECB工作模式
    print("密钥：0123456789abcdeffedcba9876543210")
    print("明文：0123456789abcdeffedcba9876543210")
    print("工作模式：ECB")

    # 创建SM4对象并输入初始密钥和工作模式
    sm4_encrypt = SM4("0123456789abcdeffedcba9876543210", 'ECB')
    # 加密
    cipher = sm4_encrypt.encrypt_txt("0123456789abcdeffedcba9876543210")
    print(f"密文：{cipher}")
    # 解密
    sm4_decrypt = SM4("0123456789abcdeffedcba9876543210", 'ECB')
    m = sm4_decrypt.decrypt_txt(cipher)
    print(f"解密结果：{m}")


    SM4普通明文加解密，CBC工作模式
    # 创建SM4对象并输入初始密钥、工作模式和初始向量
    sm4_encrypt = SM4("0123456789abcdeffedcba9876543210", 'CBC', "0123456789abcdeffedcba9876543210")
    cipher = sm4_encrypt.encrypt_txt("0123456789abcdeffedcba987654321000")
    print(cipher)
    sm4_decrypt = SM4("0123456789abcdeffedcba9876543210", 'CBC', "0123456789abcdeffedcba9876543210")
    m = sm4_decrypt.decrypt_txt(cipher)
    print(m)
    

    # SM4txt文件加解密，ECB工作模式
    sm4_encrypt = SM4("0123456789abcdeffedcba9876543210", 'ECB')
    sm4_encrypt.encrypt_file("test.txt")
    sm4_decrypt = SM4("0123456789abcdeffedcba9876543210", 'ECB')
    sm4_decrypt.decrypt_file("test.encrypt")
    

    # SM4txt文件加解密，CBC工作模式
    sm4_encrypt = SM4("0123456789abcdeffedcba9876543210", 'CBC', "0123456789abcdeffedcba9876543210")
    sm4_encrypt.encrypt_file("test.txt")
    sm4_decrypt = SM4("0123456789abcdeffedcba9876543210", 'CBC', "0123456789abcdeffedcba9876543210")
    sm4_decrypt.decrypt_file("test.encrypt")


    # 普通明文sha1
    sha1 = Hash_sha1()
    hashvalue = sha1.sha1_txt("helloworld")
    print(hashvalue)
    
    # 文件sha1
    sha1 = Hash_sha1()
    hashvalue1 = sha1.sha1_file("test.txt")
    print(hashvalue1)
    hashvalue2 = sha1.sha1_file("test_decrypt.txt")
    print(hashvalue2)


    # ElGamal签名方案
    # 系统初始化
    # 生成密钥
    egm = ElGamal.generate(1024)
    私钥
    private_x = egm.exportKey()
    # 公钥
    public_y, public_g, public_p = egm.publicKey()
    # 签名
    msg = "data"
    egm_sign = ElGamal.Sign()
    egm_sign.keyimport(public_y, public_p, public_g, private_x)
    signature1, signature2 = egm_sign.sign(msg)
    # 验证
    egm_vrfy = ElGamal.Vrfy()
    egm_vrfy.keyimport(public_y, public_p, public_g)
    result = egm_vrfy.vrfy(msg, signature1, signature2)
    
    print(f"消息：{msg}")
    print(f"签名1：{signature1}")
    # print(f"签名2：{signature2}")
    # print(f"验证结果：{result}")


