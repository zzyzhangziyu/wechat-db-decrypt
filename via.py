import win32com.client
from win32api import(
    OpenProcess,
    CloseHandle
)
from win32con import PROCESS_ALL_ACCESS
from win32process import(
    EnumProcesses,
    EnumProcessModules,
    GetModuleFileNameEx, 
)
from ctypes import *
import os
from winreg import *
import hashlib
import binascii
from time import sleep, localtime, strftime
from pysqlcipher3 import dbapi2 as sqlite

ReadProcessMemory = windll.kernel32.ReadProcessMemory

WMI = win32com.client.GetObject('winmgmts:')

def get_pid(exe):
    plist = WMI.ExecQuery(f"SELECT * FROM Win32_Process where name = '{exe}'")
    return int(plist[0].handle) if len(plist) > 0 else None

def get_module(process, dll):
    for module in EnumProcessModules(process):
        name = os.path.basename(GetModuleFileNameEx(process, module)).lower()
        if name == 'wechatwin.dll':
            return module
    return

def get_mydoc_path():
    key = OpenKey(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
    value, _ = QueryValueEx(key, "Personal")
    return value
    
def get_file_save_path():
    key = OpenKey(HKEY_CURRENT_USER, r"Software\Tencent\WeChat")
    value, _ = QueryValueEx(key, "FileSavePath")
    return value if value != 'MyDocument:' else get_mydoc_path()

pid = get_pid('wechat.exe')
process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
module = get_module(process, 'wechatwin.dll')

wechat_id_addr = c_int32()
ReadProcessMemory(process.handle, module+0xFEDBD8, byref(wechat_id_addr), 4, None)
wechat_id = create_string_buffer(21)
ReadProcessMemory(process.handle, wechat_id_addr, byref(wechat_id), 21, None)
db_path = os.path.join(get_file_save_path(),
'WeChat Files', wechat_id.value.decode(), 'Msg')
chat_msg_path = os.path.join(db_path, 'ChatMsg.db')
micro_msg_path = os.path.join(db_path, 'MicroMsg.db')

key_addr = c_int32()
ReadProcessMemory(process.handle, module+0xFF899C, byref(key_addr), 4, None)
key = create_string_buffer(32)
ReadProcessMemory(process.handle, key_addr, byref(key), 32, None)

def get_password(path, key):
    salt = open(path, 'rb').read(16)
    dk=hashlib.pbkdf2_hmac('sha1', key, salt, 64000, dklen=32)
    return binascii.hexlify(dk).decode()

chat_msg_passwd = get_password(chat_msg_path, key.raw)
micro_msg_passwd = get_password(micro_msg_path, key.raw)

micro_msg_conn = sqlite.connect(micro_msg_path)
cur = micro_msg_conn.cursor()
cur.execute('''PRAGMA key="x'%s'"''' % micro_msg_passwd)
cur.execute("PRAGMA cipher_page_size=4096")
contect = dict(cur.execute("select UserName, NickName from Contact").fetchall())


conn = sqlite.connect(chat_msg_path)
cur = conn.cursor()
cur.execute('''PRAGMA key="x'%s'"''' % chat_msg_passwd)
cur.execute("PRAGMA cipher_page_size=4096")
max_seq = -1

from wcwidth import wcswidth, wcwidth
from prettytable import PrettyTable

def padding(s, l):
    return s + ' ' * (l - wcswidth(s))

def print_recive(talker, content, timestamp):
    table = PrettyTable()
    table.padding_width = 1
    table.junction_char = '|'
    content = [''] + \
        [wrap(l, 50) for l in content.replace('\t', '    ').split('\n')] +\
        ['', '']
    table.add_column(strftime("%Y-%m-%d %H:%M:%S"+' '*20, localtime(timestamp)), content)
    table.align = 'l'
    lines = table.get_string().split('\n')
    lines = [' ' + l for l in lines]
    lines[0] = ' /' + lines[0][2:-1] + '\\'
    lines[-1] = '/-' + lines[0][2:-1] + '/'
    lines.insert(-2, lines[2])
    sign = 'From ' + contect[talker]
    lines[-2] = lines[-2][:-wcswidth(sign)-3] + sign + "  |"
    print('\n'.join(lines))
    print()


def print_send(talker, content, timestamp):
    table = PrettyTable()
    table.padding_width = 1
    table.junction_char = '|'
    width = 30
    content = ['']+[wrap(l, 50) for l in content.replace('\t', '    ').split('\n')] + ['','']
    table.add_column(strftime("%Y-%m-%d %H:%M:%S"+' '*4, localtime(timestamp)), content)
    table.align = 'l'
    lines = table.get_string().split('\n')
    lines[0] = '/' + lines[0][1:-1] + '\\'
    lines[-1] = '\\' + lines[0][1:-1] + '-\\'
    lines.insert(-2, lines[2])
    sign = 'To ' + contect[talker]
    lines[-2] = lines[-2][:-wcswidth(sign)-3] + sign + "  |"
    lines = [' ' * (width + (50-len(lines[0]))) + l for l in lines]
    print('\n'.join(lines))
    print()

from math import ceil
import re
import xml.dom.minidom
from bs4 import BeautifulSoup

def wrap(s, n):
    result = []
    buf = ''
    total_len = 0
    for c in s:
        l = wcwidth(c)
        if (total_len + l > n):
            result.append(buf)
            buf = c
            total_len = 1
        buf += c
        total_len += l

    result.append(buf)
    return '\n'.join(result)

while True:
    seq = cur.execute("select seq from sqlite_sequence where name='ChatCRMsg'").fetchall()
    if not seq:
        sleep(1)
        continue
    
    seq = seq[0][0]
    if max_seq >= seq:
        sleep(1)
        continue

    msg = cur.execute("select type, CreateTime, IsSender, strTalker, strContent from ChatCRMsg where localId > ?", (max_seq,))
    for type_id, create_time, is_sender, talker, content in msg:
        if type_id == 49:
            dom = BeautifulSoup(content, "html.parser")
            appname = dom.find('appname').text
            if (appname == '网易云音乐'):
                title = dom.find('title').text
                des = dom.find('des').text
                url = dom.find('url').text
                content = f'[音乐] {title} - {des}\n{url}'
            else:
                content = '[动画表情]'
        elif type_id == 47:
            content = '[动画表情]'
        elif type_id == 3:
            content = '[图片]'
        elif type_id == 42:
            dom = xml.dom.minidom.parseString(content)
            nickname = dom.documentElement.getAttribute('nickname')
            username = dom.documentElement.getAttribute('username')
            alias = dom.documentElement.getAttribute('alias')
            content = f'[名片] {nickname} - {alias if alias else username}'
        elif type_id == 43:
            content = '[视频]'
        elif type_id == 34:
            content = '[语音]'
        
        content = re.sub('<a.+?>(.+)</a>', r'<\1>', content)

        if (is_sender):
            print_send(talker, content, create_time)
        else:
            print_recive(talker, content, create_time)

    max_seq = seq
