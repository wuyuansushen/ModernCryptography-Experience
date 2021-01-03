import md5
import RSA
import DES
import re


def encrypt():
    print("--------------------加密过程开始--------------------")
    print("--------------------MD5加密开始--------------------")
    mess=input("请输入想加密的消息(默认为hello):") or "hello"
    origin=mess
    md5Tmp=md5.md5hash(mess)
    print(f"明文长度为: {origin.__len__()}\n输入的明文的MD5值为: {md5Tmp}")
    print("--------------------MD5加密结束--------------------\n")
    print("--------------------RSA加密开始--------------------")
    p = int(input("输入RSA密码算法的p值(必须为素数,默认值为47):") or "47")
    q = int(input("输入RSA密码算法的q值(必须为素数且不能与上面的值相同，默认值为463):") or "463")
    ListOut = RSA.generate_key_pair(p,q)
    encrypted = RSA.encrypt(ListOut[0],ListOut[1], md5Tmp)
    encrypted_msg=' '.join(map(lambda x: str(x), encrypted))
    print(f"RSA公钥为: ({ListOut[0]},{ListOut[1]})\nRSA私钥的key值为: {ListOut[2]}\nRSA私钥的n值为: {ListOut[1]}\nRSA密文为:\n{encrypted_msg}\n")
    print("--------------------RSA加密结束--------------------\n")
    print("--------------------DES加密开始--------------------")
    combine=origin+encrypted_msg
    noPairKey=input("输入您的DES密钥(默认值为hello123，必须为8个):") or "hello123"
    desObject=DES.des()
    finalOut=desObject.encrypt(noPairKey,combine,padding=True)
    f=open("encrypted.txt","wb")
    f.write(bytes(finalOut,'utf-8'))
    f.close()
    print(f"DES明文为:\n{combine}\nDES密文为:\n{finalOut}\n密文已编码后写入encrypted.txt文件中")
    print("--------------------DES加密结束--------------------")
    print("--------------------加密过程结束--------------------\n")

def decrypt():
    print("--------------------解密过程开始--------------------")
    print("--------------------DES解密开始--------------------")
    desObject2=DES.des()
    print("正在从encrypted.txt中获取密文.....")
    f=open("encrypted.txt","rb")
    encrypted=(f.read()).decode("utf-8")
    f.close()
    noPairKey2=input("输入您的DES密钥(默认为hello123):") or "hello123"
    unSymm=desObject2.decrypt(noPairKey2,encrypted)
    length=int(input("请输入源数据长度(默认为hello的5):") or "5")
    plainText=unSymm[0:length]
    print(f"源数据明文为为:{plainText}")
    md5A=md5.md5hash(plainText)
    print(f"源数据明文计算出的MD5值为:\n{md5A}")
    decryptMes=unSymm[length:]
    decryptMes2=decryptMes.split(' ')
    for i in range(0,(len(decryptMes2))-1):
        decryptMes2[i]=int(decryptMes2[i])
    decryptMes2[len(decryptMes2)-1]=int(re.search(r'\d+', decryptMes2[len(decryptMes2)-1]).group())
    print("--------------------DES解密结束--------------------\n")
    print("--------------------RSA解密开始--------------------")
    print(f"获得RSA密文为:")
    for p in range(0,(len(decryptMes2)-1)):
        print(f"{decryptMes2[p]} ",end='')
    print()
    key=int(input("请输入您的私钥的key:"))
    n=int(input("请输入您的私钥的n:"))
    md5B=RSA.decrypt(key,n,decryptMes2)
    print(f"RSA解密所得的MD5值为:\n{md5B}")
    print("--------------------RSA解密结束--------------------\n")
    print("--------------------MD5比对开始--------------------")
    print(f"明文的文本计算出的MD5值为: {md5A}")
    print(f"经过RSA解密所得的MD5值为: {md5B}")
    print()
    if(md5A==md5B):
        print("结论: 比对结果相同，没有错误")
    else:
        print("结论: 比对结果不同，出现了错误")
    print("--------------------MD5比对结束--------------------\n")
    print("--------------------解密过程结束--------------------")


if __name__ == '__main__':
    choice=input("请输入您的选择.加密输入e，解密输入d\n您的选择:")
    if (choice=='e'):
        encrypt()
    elif(choice=='d'):
        decrypt()
    else:
        print("输入有误")
