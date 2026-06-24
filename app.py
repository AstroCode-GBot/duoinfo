import os
import base64
import asyncio
import time
import httpx
import json
import urllib3
import requests
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as crypto_pad, unpad as crypto_unpad
from werkzeug.exceptions import HTTPException
from google.protobuf import json_format
from google.protobuf.message import Message

from Pb2 import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2, SpecialFriend_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Config:
    PORT = int(os.environ.get("PORT", 5000))
    DEBUG = os.environ.get("DEBUG", "False").lower() == "true"
    MAIN_KEY = base64.b64decode(os.environ.get("MAIN_KEY", "WWcmdGMlREV1aDYlWmNeOA=="))
    MAIN_IV = base64.b64decode(os.environ.get("MAIN_IV", "Nm95WkRyMjJFM3ljaGpNJQ=="))
    LOGIN_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
    
    CLIENT_VERSION = "1.126.1"
    CLIENT_VERSION_CODE = "2019120270"
    UNITY_VERSION = "2018.4.11f1"
    RELEASE_VERSION = "OB54"
    MSDK_VERSION = "5.5.2P3"
    USER_AGENT_MODEL = "ASUS_Z01QD"
    ANDROID_OS_VERSION = "Android 10"

    USER_AGENT = f"Dalvik/2.1.0 (Linux; U; {ANDROID_OS_VERSION}; {USER_AGENT_MODEL} Build/RKQ1.211119.001)"
    REGION_LANG = {"BD": "bn"}
    BOT_CREDENTIALS = {
        "BD": {"uid": "4343645299", "password": "C5C216587364AD7247730F433CABA4A5C91C6889BCCC2A4D8105E3D7297B5CE2"}
    }
    REGION_API_ENDPOINTS = {
        "BD": "https://clientbp.ggpolarbear.com/GetWishListItems"
    }
    ACCOUNTS = {
        "BD": "uid=4343645299&password=C5C216587364AD7247730F433CABA4A5C91C6889BCCC2A4D8105E3D7297B5CE2"
    }

    @staticmethod
    def get_account():
        return Config.ACCOUNTS.get("BD")

app = Flask(__name__)
CORS(app)
app.json.sort_keys = False

GUEST_TOKENS = {}
CACHED_TOKENS = {}

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type):
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key_bytes = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    api_iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key_bytes, AES.MODE_CBC, api_iv)
    return cipher.encrypt(crypto_pad(plain_text, AES.block_size)).hex()

def login_process_guest(uid, password):
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "User-Agent": f"GarenaMSDK/{Config.MSDK_VERSION}({Config.USER_AGENT_MODEL};{Config.ANDROID_OS_VERSION};en;US;)",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": Config.LOGIN_KEY, "client_id": "100067"}
        resp = requests.post(url, headers=headers, data=body, timeout=15, verify=False)
        data = resp.json()
        if 'access_token' not in data:
            return None
        access_token, open_id = data['access_token'], data['open_id']
        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        host = "loginbp.ggpolarbear.com"
        lang = Config.REGION_LANG.get("BD", "en")
        binary_head = b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.120.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02'
        binary_tail = b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019119621\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        full_payload = binary_head + lang.encode("ascii") + binary_tail
        temp_data = full_payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        temp_data = temp_data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        final_body = bytes.fromhex(encrypt_api(temp_data.hex()))
        headers = {
            "User-Agent": f"Dalvik/2.1.0 (Linux; U; {Config.ANDROID_OS_VERSION}; {Config.USER_AGENT_MODEL} Build/PI)",
            "Content-Type": "application/x-www-form-urlencoded", "Host": host, "X-GA": "v1 1", "ReleaseVersion": Config.RELEASE_VERSION
        }
        resp = requests.post(url, headers=headers, data=final_body, verify=False, timeout=15)
        if "eyJ" in resp.text:
            token = resp.text[resp.text.find("eyJ"):]
            end = token.find(".", token.find(".") + 1)
            return token[:end + 44] if end != -1 else None
        return None
    except Exception:
        return None

async def fetch_duo_info(uid):
    try:
        creds = Config.BOT_CREDENTIALS["BD"]
        token = GUEST_TOKENS.get("BD")
        if not token:
            token = login_process_guest(creds["uid"], creds["password"])
            if token: 
                GUEST_TOKENS["BD"] = token
        if not token: 
            return None
        def to_varint(n):
            res = bytearray()
            while n >= 0x80:
                res.append((n & 0x7f) | 0x80)
                n >>= 7
            res.append(n)
            return bytes(res)
        payload_raw = b"\x08" + to_varint(int(uid))
        aes_key = b'Yg&tc%DEuh6%Zc^8'
        aes_iv = b'6oyZDr22E3ychjM%'
        payload_enc = AES.new(aes_key, AES.MODE_CBC, aes_iv).encrypt(crypto_pad(payload_raw, 16))
        endpoint = Config.REGION_API_ENDPOINTS["BD"].replace("GetWishListItems", "GetSpecialFriendList")
        headers = {
            'User-Agent': f'Dalvik/2.1.0 (Linux; U; {Config.ANDROID_OS_VERSION})',
            'Connection': 'Keep-Alive',
            'Authorization': f'Bearer {token}',
            'X-Unity-Version': Config.UNITY_VERSION,
            'X-GA': 'v1 1',
            'ReleaseVersion': Config.RELEASE_VERSION,
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.post(endpoint, headers=headers, content=payload_enc)
            if resp.status_code != 200:
                token = login_process_guest(creds["uid"], creds["password"])
                if token:
                    GUEST_TOKENS["BD"] = token
                    headers['Authorization'] = f'Bearer {token}'
                    resp = await client.post(endpoint, headers=headers, content=payload_enc)
            if resp.status_code == 200 and resp.content:
                try:
                    decrypted = crypto_unpad(AES.new(aes_key, AES.MODE_CBC, aes_iv).decrypt(resp.content), 16)
                except Exception:
                    decrypted = resp.content
                response = SpecialFriend_pb2.SpecialFriendResponse()
                response.ParseFromString(decrypted)
                if response.HasField("duo_info"):
                    duo = response.duo_info
                    score = duo.score
                    calc_level = 1
                    if score < 101: calc_level = 1
                    elif score < 301: calc_level = 2
                    elif score < 501: calc_level = 3
                    elif score < 801: calc_level = 4
                    elif score < 1201: calc_level = 5
                    else: calc_level = 6
                    
                    status_str = "Active" if getattr(duo, "status", 0) == 2 else "Inactive"
                    created_date = "N/A"
                    if getattr(duo, "creation_timestamp", 0) > 0:
                        created_date = datetime.datetime.fromtimestamp(duo.creation_timestamp).strftime('%Y-%m-%d %I:%M:%S %p')
                    
                    return {
                        "PartnerUid": str(duo.partner_uid),
                        "DuoLevel": calc_level,
                        "IntimacyScore": score,
                        "DaysActive": duo.days_active,
                        "Status": status_str,
                        "CreationDate": created_date
                    }
    except Exception:
        pass
    return None

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': Config.USER_AGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip", 
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt():
    account = Config.get_account()
    token_val, open_id = await get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(Config.MAIN_KEY, Config.MAIN_IV, proto_bytes)
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {
        'User-Agent': Config.USER_AGENT, 
        'Connection': "Keep-Alive", 
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 
        'Expect': "100-continue",
        'X-Unity-Version': Config.UNITY_VERSION, 
        'X-GA': "v1 1", 
        'ReleaseVersion': Config.RELEASE_VERSION
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        CACHED_TOKENS["BD"] = {
            'token': f"Bearer {msg.get('token','0')}",
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200
        }

async def get_token_info():
    info = CACHED_TOKENS.get("BD")
    if info and time.time() < info['expires_at']:
        return info['token'], info['server_url']
    await create_jwt()
    info = CACHED_TOKENS["BD"]
    return info['token'], info['server_url']

async def get_basic_player_info(uid):
    try:
        payload = await json_to_proto(json.dumps({'a': int(uid), 'b': 7}), main_pb2.GetPlayerPersonalShow())
        data_enc = aes_cbc_encrypt(Config.MAIN_KEY, Config.MAIN_IV, payload)
        token, server = await get_token_info()
        headers = {
            'User-Agent': Config.USER_AGENT, 
            'Connection': "Keep-Alive", 
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream", 
            'Expect': "100-continue",
            'Authorization': token, 
            'X-Unity-Version': Config.UNITY_VERSION, 
            'X-GA': "v1 1",
            'ReleaseVersion': Config.RELEASE_VERSION
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(server + "/GetPlayerPersonalShow", data=data_enc, headers=headers)
            if resp.status_code == 200 and resp.content:
                data = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))
                return data.get("basicInfo", {}).get("nickname", "Unknown")
    except Exception:
        pass
    return "Unknown"

def run_async(coro):
    new_loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(new_loop)
        return new_loop.run_until_complete(coro)
    finally:
        new_loop.close()
        asyncio.set_event_loop(None)

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException): 
        return jsonify({"error": e.description}), e.code
    return jsonify({"error": "Internal Server Error"}), 500

@app.route('/api/duo')
def get_duo_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Missing UID parameter. Example: /api/duo?uid=123456"}), 400
    async def fetch_all():
        player_name_task = get_basic_player_info(uid)
        duo_info_task = fetch_duo_info(uid)
        p_name, d_info = await asyncio.gather(player_name_task, duo_info_task)
        partner_name = "Unknown"
        if d_info and d_info.get("PartnerUid"):
            partner_name = await get_basic_player_info(d_info["PartnerUid"])
        return p_name, partner_name, d_info
    player_name, partner_name, duo_info = run_async(fetch_all())
    if player_name == "Unknown":
        return jsonify({"Error": "Player not found or not in Bangladesh server", "PlayerUID": uid}), 404
    if not duo_info:
        return jsonify({"PlayerName": player_name, "PlayerUID": uid, "DuoStatus": "No Active Duo Found"}), 200
    return jsonify({
        "PlayerName": player_name,
        "PlayerUID": uid,
        "DuoPartnerName": partner_name,
        "DuoPartnerUID": duo_info["PartnerUid"],
        "DuoLevel": duo_info["DuoLevel"],
        "DuoDays": duo_info["DaysActive"],
        "DuoScore": duo_info["IntimacyScore"],
        "DuoStatus": duo_info["Status"],
        "DuoCreationDate": duo_info["CreationDate"]
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=Config.PORT, debug=Config.DEBUG)
