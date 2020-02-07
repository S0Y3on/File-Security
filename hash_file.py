# -*- coding:utf-8 -*-
import hashlib


"""
해시 모드

md5, sha256, sah512

"""
hash_modes = {
            '1': 'md5',
            '2': 'sha256',
            '3': 'sha512'

              }

def select_hash():

    """
    해시 모드 선택
    :return: 해시 모드

    """
    for key, value in hash_modes.items():
        print(key + ". " + value)

    select_mode = input("select hash : ")
    return select_mode


def hash_file(filename):

    """
    :param filename: 해시할 파일 이름
    :return: value(파일의 해시값)
    """
    hash_mode = select_hash()

    f = open(filename, 'rb')
    data = f.read()
    f.close()
    value = ""
    if hash_mode == '1':
        value = hashlib.md5(data).hexdigest()
        print('MD5: '+ value)
    elif hash_mode == '2':
        value = hashlib.sha256(data).hexdigest()
        print('SHA256: '+ value)
    elif hash_mode == '3':
        value = hashlib.sha512(data).hexdigest()
        print('SHA512: '+ value)

    store_hash(hash_mode, filename, value)
    return value


def check_Integrity(filename1, filename2):

    """

    :param filename1: 해시값을 비교할 파일1
    :param filename2: 해시값을 비교할 파일2
    :result: filename1, filename2의 해시값이 동일 => 무결성 증명
    """

    hash1 = hash_file(filename1)
    hash2 = hash_file(filename2)
    if (hash1 == hash2):
        print("Integrity")
    else:
        print("Compromise Integrity")


def store_hash(hash_mode, file_name, value):

    """
    :param hash_mode: 해시 모드
    :param file_name: 파일 이름
    :param value: 해시값
    :result: admin.txt에 해시 모드 \t 파일이름 \t 해시값 \n 저장
    """

    hash_name = hash_modes[hash_mode]

    file = open('dream/admin.txt', 'a')
    file.write(hash_name + "\t" + file_name + "\t" + value + "\n")
    file.close()


def search_hash(file_name):

    """
    :param file_name: 해시값을 검색할 파일 이름
    :return: val(파일의 해시값)
    admin.txt에서 file_name에 해당하는 해시값 추출
    """

    dec_name, extension = file_name.split(".")
    fname = dec_name.split("_")[0]
    fname = fname + "." + extension
    file = open('dream/admin.txt', 'r')
    line = file.readline()
    while line != "\n":
        hname, f_name, val = line.split("\t")
        if f_name == fname:
            file.close()
            print(fname, val)
            return val.rstrip("\n")
        line = file.readline()
