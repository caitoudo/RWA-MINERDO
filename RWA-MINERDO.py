import os
import json
import uuid
import requests
import random
import time
from mnemonic import Mnemonic
from bip32 import BIP32
from eth_account import Account
from web3 import Web3
from eth_account.messages import encode_defunct
import eth_keys

# 改成自己的邀请码
yqm = ''


#下面勿动
PROXY_FILE = 'proxy.txt'
w3 = Web3()

def get_proxy_list():
    proxy_list = []
    try:
        with open(PROXY_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    proxy_list.append(line)
    except FileNotFoundError:
        print(f"未找到代理文件 {PROXY_FILE}！")
        exit(1)
    return proxy_list

def generate_mnemonic():
    mnemo = Mnemonic("english")
    words = mnemo.generate(strength=256)
    return mnemo, words

def mnemonic_to_seed(mnemo, mnemonic_phrase):
    return mnemo.to_seed(mnemonic_phrase)

def seed_to_private_key(seed):
    bip32 = BIP32.from_seed(seed)
    private_key = bip32.get_privkey_from_path("m/44'/60'/0'/0/0")
    return private_key

def private_key_to_address(private_key):
    account = Account.from_key(private_key)
    return account.address

def get_nonce(proxy=None):
    nonce_url = "https://event.goldstation.io/api-v2/public/nonce"
    headers = {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "if-none-match": 'W/"73-GBq0iT+6jJ82qPnU1Xp3wYCWXbA"',
        "priority": "u=1, i",
        "referer": f"https://event.goldstation.io/?referral={yqm}",
        "sec-ch-ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "x-api-key": "03ad7ea4-2b75"
    }
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None

    response = requests.get(nonce_url, headers=headers, proxies=proxies)
    if response.status_code == 200:
        response_data = response.json()
        if response_data.get("success") and "data" in response_data and "nonce" in response_data["data"]:
            nonce_value = response_data["data"]["nonce"]
            print("Nonce 为:", nonce_value)
            return nonce_value
        else:
            print("响应中不包含 nonce 值。")
            return None
    else:
        print(f"获取 nonce 失败。状态码: {response.status_code}")
        return None

def sign_message(private_key, message):
    try:
        if isinstance(private_key, str):
            private_key = private_key.replace("0x", "")
            private_key_bytes = bytes.fromhex(private_key)
        else:
            private_key_bytes = private_key

        if len(private_key_bytes) != 32:
            raise ValueError(f"私钥长度无效。期望 32 字节，实际得到 {len(private_key_bytes)} 字节。")

        account = w3.eth.account.from_key(private_key_bytes)
        encoded_message = encode_defunct(text=message)
        signed_message = account.sign_message(encoded_message)
        return signed_message.signature.hex()

    except eth_keys.exceptions.ValidationError as e:
        raise ValueError(f"私钥格式无效: {e}") from e
    except Exception as e:
        raise ValueError(f"签名失败: {e}") from e

def login(signature, nonce_value, wallet_address, private_key, mnemonic_phrase, proxy):
    login_url = "https://event.goldstation.io/api-v2/user/login"
    headers = {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "origin": "https://event.goldstation.io",
        "priority": "u=1, i",
        "referer": f"https://event.goldstation.io/?referral={yqm}",
        "sec-ch-ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "x-api-key": "03ad7ea4-2b75"
    }
    data = {
        "signature": '0x' + signature,
        "nonce": nonce_value,
        "address": wallet_address,
        "walletCode": 1,
        "clickPower": 0.016,
        "uuid": str(uuid.uuid4()),
        "referralCode": yqm
    }
    proxies = {
        "http": proxy,
        "https": proxy
    } if proxy else None
    try:
        response = requests.post(login_url, headers=headers, json=data, proxies=proxies)
        if response.status_code == 200:
            response_data = response.json()
            token = response_data["data"]["token"]
            with open("token.txt", "a") as file:
                file.write(f"{data['uuid']}||{token}\n")
            with open("qb.txt", "a") as file:
                file.write(f"{data['uuid']}||{wallet_address}||0x{private_key.hex()}||{mnemonic_phrase}\n")
            print("邀请成功，数据已保存到txt文件中")
        else:
            print(f"登录失败。状态码: {response.status_code}")
            print("响应内容:", response.text)

    except requests.exceptions.RequestException as e:
        print(f"请求失败: {e}")

if __name__ == "__main__":
    proxies_list = get_proxy_list()
    for proxy in proxies_list:
        print(f"当前使用代理: {proxy}")
        try:
            mnemo, mnemonic_phrase = generate_mnemonic()
            print(f"助记词: {mnemonic_phrase}")
            seed = mnemonic_to_seed(mnemo, mnemonic_phrase)
            print(f"种子: {seed.hex()}")
            private_key = seed_to_private_key(seed)
            print(f"以太坊私钥: 0x{private_key.hex()}")
            wallet_address = private_key_to_address(private_key)
            print(f"以太坊钱包地址: {wallet_address}")
            nonce_value = get_nonce(proxy=proxy)

            if nonce_value:
                signature = sign_message(private_key, nonce_value)
                print("签名结果:", '0x' + signature)
                login(signature, nonce_value, wallet_address, private_key, mnemonic_phrase, proxy)

        except Exception as e:
            print(f"出现错误: {e}")
        wait_time = random.uniform(1, 2)
        print(f"随机等待 {wait_time:.2f} 秒...")
        time.sleep(wait_time)

    print("所有代理 IP 已处理完毕！")
