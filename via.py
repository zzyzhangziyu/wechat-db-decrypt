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
from time import sleep
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

from wcwidth import wcswidth
from prettytable import PrettyTable

def padding(s, l):
    return s + ' ' * (l - wcswidth(s))

def print_recive(talker, content):
    table = PrettyTable()
    table.padding_width = 1
    content = ['  ' + l for l in content.split('\n')] + ['']
    table.add_column(padding(contect[talker], 40), content)
    table.align = 'l'
    lines = table.get_string().split('\n')
    lines = lines[:-1]
    print('\n'.join(lines))
    print()


def print_send(talker, content):
    table = PrettyTable()
    table.padding_width = 1
    content = ['  ' + l for l in content.split('\n')] + ['']
    table.add_column(padding(contect[talker], 40), content)
    table.align = 'l'
    lines = table.get_string().split('\n')
    lines = ['         ' + l for l in lines]
    lines = lines[:-1]
    print('\n'.join(lines))
    print()

while True:
    seq = cur.execute("select seq from sqlite_sequence where name='ChatCRMsg'").fetchall()
    if not seq:
        sleep(1)
        continue
    
    seq = seq[0][0]
    if max_seq >= seq:
        sleep(1)
        continue

    msg = cur.execute("select IsSender, strTalker, strContent from ChatCRMsg where localId > ?", (max_seq,))
    for is_sender, talker, content in msg:
        if (is_sender):
            print_send(talker, content)
        else:
            print_recive(talker, content)

    max_seq = seq
