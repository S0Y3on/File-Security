# -*- coding:utf-8 -*-

import os
import sys
import hash_file
from Crypto.Cipher import AES


'''
작업 디렉토리 : work_directory

dream/ :  Default Directory
enc_dir : 암호화한 파일이 저장되는 디렉토리
dec_dir : 복호화한 파일이 저장되는 디렉토리

'''

work_directory = {
    "default_path": "dream/",
    "enc_dir": "dream/Enctrypt/",
    "dec_dir": "dream/Decrypt/"
}


AES_MODE = {
        "1": "AES.MODE_ECB",
        "2": "AES.MODE_CBC"
}

class CipherFile:
    '''

    CipherFile Class : 파일 암/복호화 클래스
    AES EBC,CBC 암/복호화 사용
    => AES.new(self.pad_key(self.key), AES.모드, (IV=self.iv))

    '''
    def __init__(self):
        self.iv = ("0" * 16).encode()
        self.key = ''
        self.encrypted = False
        self.admin_pw = 'qwe123!@##'



    def select_mode(self):

        """
        :return: AES 모드 값
        AES 모드를 선택
        """
        for key,value in AES_MODE.items():
            print(key + ". " + value)

        mode = input("select mode : ")

        return AES_MODE[mode]



    def pad_key(self, key):

        """
        pad_key(self, key)
        argument : key = 사용자가 입력한 암호화 password
        return : key (16 byte로 패딩된 사용자 패스워드 값)

        사용자가 입력하는 password의 길이가 16byte 미만일때, password를 패딩하여 16byte로 만들어 return
        ex) password(key) = "123456789"  9byte  ----->  "1234567890000000"  16byte
        """
        key = key.ljust(16, '0')
        key = key.encode()
        return key

    def pad_plaintext(self, plaintext):

        """
        :param plaintext: 암호화 할 파일의 평문 데이터
        :return: padding_len(패딩한 길이), plaintext(패딩된 평문)

        암호화 할 파일의 평문의 길이가 16byte 배수가 아닐때, 16byte 배수가 되도록 패딩
        ex) plaintext = "abcde"  5byte ----->  "abcde00000000000" 16byte
        """

        p_len = len(plaintext)
        Remainder = p_len % 16
        padding_len = 16 - Remainder


        if  p_len % 16 == 0:
            return 0, plaintext

        else:
            plaintext = plaintext.ljust(p_len + padding_len, b'0')
            fd = len(plaintext)
            return padding_len, plaintext

    def EncryptFile(self, filename, admin=False, find=False):

        """
        :param filename: 암호화 할 파일 이름
        :param admin: False : filename -> 사용자가 암호화할 파일 , True:  filename -> fileinfo*.pw
        :param find: True : fileinfo*.pw 에서  암호화된 파일의 패스워드(key)를 찾고있음을 표시
        :result : test.txt -> test_enc.txt
        """
        mode = ''
        if admin:
            infile = open("dream/" + filename, 'rb')
        else:
            infile = open(filename, 'rb')
            mode = self.select_mode()

        p = infile.read()
        infile.close()
        padding_len, p = self.pad_plaintext(p)
        if not admin:
            self.key = input("Input Password : ")
            fname, extension = filename.split(".")
            enc_filename = fname + "_enc." + extension
            ## Store password in cipher_info.txt
            self.store_password(enc_filename, self.key, padding_len,mode)
            #####
            outfile = open(work_directory['enc_dir'] + enc_filename, 'wb')
            print("\nEncrypt {} --------> {}".format(filename,enc_filename))

        else:
            fname, extension = filename.split(".")
            enc_filename = fname[:8] + str(padding_len) + '.' + extension
            outfile = open(work_directory['default_path'] + enc_filename, 'wb')
            if not find:
                infile.close()
                if filename != enc_filename:
                    os.remove("dream/" + filename)
        if admin:
            cipher = AES.new(self.pad_key(self.admin_pw), AES.MODE_CBC, IV=self.iv)
        elif mode == "AES.MODE_ECB":
            cipher = AES.new(self.pad_key(self.key), AES.MODE_ECB)
        elif mode == "AES.MODE_CBC":
            cipher = AES.new(self.pad_key(self.key), AES.MODE_CBC, IV=self.iv)
        enc_p = cipher.encrypt(p)
        outfile.write(enc_p)
        outfile.close()




    def store_password(self, filename, key, padding_len,mode):

        """
        :param filename: 암호화할 파일 이름
        :param key: 암호화할 파일의 패스워드(key)
        :param padding_len: 암호화할 파일이 패딩된 길이

        fileinfo*.pw
        암호화 파일의 정보(패스워드(key), 패딩된 길이)가 저장
        admin에 의해 암/복호화 되어 관리됨
        * : fileinfo*.pw가 암호화 될 시에 패딩된 길이값이 들어감, 패딩된 길이는 복호화할시 필요
         Ex) fileinfo0.pw => fileinfo0.pw에 저장된 데이터의 길이가 16의 배수
        저장 포멧 : filename key(=password) padding_len mode\n
        """

        fileinfo = findfileinfo()
        # 1. decrypt fileinfo.pw
        self.DecryptFile(fileinfo, True)
        # 2. store filename,key in fileinfo.pw
        f = open("dream/" + fileinfo, "a")
        f.write(filename + " " + key + " " + str(padding_len) +" "+ mode +"\n")
        f.close()
        # 3. encrypt fileinfo.pw
        self.EncryptFile(fileinfo, True)

    def find_password(self, filename):

        """
        :param filename: 복호화할 파일이름
        :return: key(복호화할 파일의 패스워드), padding_len(패딩된 길이)

        """
        fileinfo = findfileinfo()
        # 1. decrypt fileinfo.pw
        self.DecryptFile(fileinfo, True)
        # 2. find filnames'key(=password) and padding_len
        f = open("dream/" + fileinfo, "r")
        line = f.readline()
        while line != "\n":
            fname, key, padding_len, mode = line.split(" ")
            if fname == filename:
                f.close()
                # 3. encrypt fileinfo.pw
                self.EncryptFile(fileinfo, True, True)
                # 4. return key(=password) padding_len
                return key, int(padding_len), mode.rstrip("\n")
            line = f.readline()




    def DecryptFile(self, filename, admin=False):

        """
        :param filename: 복호화할 파일 이름
        :param admin: False : filename -> 사용자가 복호화할 파일 , True:  filename -> fileinfo*.txt
        :result : test_enc.txt -> test_dec.txt
        """
        if not admin:
            key_value, padding_len, mode = self.find_password(filename)

            passWord = input("input password: ")
            infile = open(work_directory['enc_dir'] + filename, 'rb')
            enc_p = infile.read()
            infile.close()
            fname, extension = filename.split(".")
            dec_filename = fname[:-4] + "_dec." + extension

            if key_value == passWord:
                self.key = passWord

                if mode == "AES.MODE_ECB":
                    cipher = AES.new(self.pad_key(self.key), AES.MODE_ECB)
                elif mode == "AES.MODE_CBC":
                    cipher = AES.new(self.pad_key(self.key), AES.MODE_CBC, self.iv)
                outfile = open(work_directory['dec_dir'] + dec_filename, 'wb')
                plain = cipher.decrypt(enc_p)
                if padding_len == 0:
                    outfile.write(plain[:])
                else:
                    outfile.write(plain[:-padding_len])
                outfile.close()
                print("\nDecrypt {} --------> {}".format(filename,dec_filename))
                print("Complete Decrypt File!!!")
            else:
                print("password is incorrect.")

        else:
            infile = open(work_directory['default_path'] + filename, 'rb')
            enc_p = infile.read()
            infile.close()
            fname, extension = filename.split(".")
            padding_len = int(fname[8:])


            cipher = AES.new(self.pad_key(self.admin_pw), AES.MODE_CBC, self.iv)
            outfile = open(work_directory['default_path'] + filename, 'wb')
            plain = cipher.decrypt(enc_p)
            if padding_len==0:
                outfile.write(plain[:])
            else:
                outfile.write(plain[:-padding_len])
            outfile.close()

def PrintFileList(path):

    """
    :param path:  출력할 파일의 경로
    :result: 해당 경로의 파일 리스트 출력

    """

    File = []
    file_list = os.listdir("./" + path)
    for fname in file_list:
        if fname[0] == '.':
            continue
        if os.path.isfile("./" + path + "/" + fname):
            File.append(fname)
    count = 0
    for num, fname in enumerate(File):
        if count == 4:
            print()
            count=0
        print("{0}. {1:<8}".format(num+1,fname),end="\t")
        count+=1
    print()

def findfileinfo():

    """
    dream 디렉토리에서 fileinfo*.pw 검색
    :return: fileinfo*.pw 의 파일이름

    """

    for fname in os.listdir("./dream"):
        if fname.endswith(".pw"):
            return fname


def make_directory(path):
    try:
        if not (os.path.isdir(path)):
            os.makedirs(os.path.join(path))
    except OSError as e:
        if e.errno != e.EEXIST:
            print("Faild to create directory")
            raise


def main():
    """
    기본 작업 디렉토리 생성 및 fileinfo0.pw 생성

    기능

    1. Encrypt File
    2. Decrypt File
    3. Check Integrity
    4. check_dir
    5. Hash
    6. Exit

    """
    make_directory(work_directory["default_path"])
    make_directory(work_directory["enc_dir"])
    make_directory(work_directory["dec_dir"])

    c = CipherFile()

    if findfileinfo() == None:
        f = open("dream/fileinfo0.pw", "a")
        f.close()



    while True:
        print("-------------------Chose Mode----------------------\n")
        print("1. Encrypt File")
        print("2. Decrypt File")
        print("3. Check Integrity")
        print("4. check_dir")
        print("5. Hash")
        print("6. Exit\n\n")
        print("===============================File List=================================")
        PrintFileList("./")
        print("=========================================================================")
        mode = input("mode number : ")
        if mode == '1':
            filename = input("Input Filename for Encrypt : ")
            c.EncryptFile(filename)
            print("Complete Encrypt File!!!")
        elif mode == '2':
            PrintFileList(work_directory['enc_dir'])
            filename = input("Input Filename for Decrypt : ")
            c.DecryptFile(filename)
        elif mode == '3':
            print("Check Integrity file name (2 file) : ")
            filename1, filename2 = map(str, input().split())
            hash_file.check_Integrity(filename1, filename2)

        elif mode == '4':
            print("==============================Encrypted==================================")
            PrintFileList(work_directory['enc_dir'])
            print("=========================================================================\n")
            print("==============================Decrypted==================================")
            PrintFileList(work_directory['dec_dir'])
            print("=========================================================================\n")

        elif mode == '5':
            filename = input("Input Filename for Hash : ")
            hash_file.hash_file(filename)

        elif mode == '6':
            sys.exit()


main()