# Crypto

以下内容对Crypto库中各模块功能具体介绍，main.py中给出了各模块调用方式。

## Math模块

该模块调用了python自带的数学库`math`以及随机数库`random`，分别实现了求最大公因数函数`gcd()`、扩展欧几里得算法函数`extend_euclid()`、求逆元函数`inverse()`、快速模幂函数`fastmod()`、米勒-拉宾素性检测函数`isPrime()`、生成大素数算法`generate_prime_number()`，以及字节转整数函数`str2long()`和整数转字节`long2str()`。
## Cipher模块

Cipher模块实现了分组加密SM4类的设计和SHA-1类的设计。

### SM4

SM4类包含普通明文加解密和文件加解密的方法设计，并且分别设计了ECB工作模式和CBC工作模式。除此之外，考虑到可能的错误输入，分别设计了密钥长度错误、工作模式选择错误、初始向量错误的报错情况。

### SHA-1

SHA-1类包含对普通明文和文件的求SHA-1哈希值的方法。

## PublicKey模块

PublicKey模块实现了RSA公钥密码体制的类的实际和ElGamal数字签名的类的设计。

### RSA

RSA类包括三个子类。初始化类`generate`包含初始化设置公钥和私钥的方法；加密类`Encrypt`包含导入公钥和加密方法；解密类`Decrypt`包含导入公私钥和解密方法。

### ElGamal

ElGamal类包括三个子类。初始化类generate包含初始化设置公钥和私钥的方法；签名类Sign包含导入公私钥和签名方法；验证类Vrfy包含导入公私钥和验证方法。
