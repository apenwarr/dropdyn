import struct, hmac, hashlib

PROTO_VERSION = 0x00


class _Err:
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg

    def __cmp__(self, b):
        a = self.code
        if isinstance(b, _Err):
            b = b.code
        return cmp(a,b)

    def __repr__(self):
        return repr((('0x%02x' % self.code), self.msg))


SUCCESS    = _Err(0x00, 'success')
EPERM      = _Err(0x30, 'permission denied')
EPERM_SELF = _Err(0x31, "permission denied: can't disable yourself")
EPERM_INHERITED = _Err(0x32,
                       "permission denied: inherited from a parent domain")
EVERSION   = _Err(0xf0, 'unknown protocol version')
ECOMMAND   = _Err(0xf1, 'unknown command')
EHMAC      = _Err(0xf2, 'message failed authenticity check')
EINVAL     = _Err(0xf3, 'invalid argument')
EREPLAY    = _Err(0xff, 'replay protection: resend with a new serial number')


class Error(Exception):
    def __init__(self, code, msg = None):
        if isinstance(code, _Err):
            self.code = code.code
            self.msg = code.msg
        else:
            self.code = code
            self.msg = '(unknown error)'
        if msg:
            self.msg = msg

    def __str__(self):
        return '%d: %s' % (self.code, self.msg)


class Cmd:
    EmailMe = 0x00
    
    KeyGen = 0x11
    Rekey = 0x12

    EmailList = 0x20
    EmailAdd = 0x21
    EmailDel = 0x22

    NameList = 0x30
    NameAdd = 0x31
    NameDel = 0x32

    IdList = 0x40
    IdAdd = 0x41
    IdDel = 0x42

    Log = 0x70

    Response = 0x80

    def is_query(cmd):
        return (cmd & 0x80) == 0

    def is_response(cmd):
        return (cmd & 0x80) != 0

    @staticmethod
    def find(val):
        if isinstance(val, tuple):
            val = val[0]
        for k,v in Cmd.__dict__.items():
            if v == val or (isinstance(v, tuple) and v[0] == cmd):
                return k,v

    def str(cmd):
        rv = Cmd.find(cmd)
        if not rv:
            raise KeyError(cmd)
        return rv[0]


def _hmac(key, content):
    return hmac.new(key, content, hashlib.sha1).digest()[:10]


def _keyid(key):
    return hashlib.sha1(key).digest()[:6]
        

def pack(key, serial, cmd, content):
    keyid = _keyid(key)
    buf = struct.pack('!BB6sQ', PROTO_VERSION, cmd, keyid, serial) + content
    return buf + _hmac(key, buf)


def unpack(pkt, key_lookup):
    (ver,cmd) = struct.unpack('!BB', pkt[0:2])
    if ver != PROTO_VERSION:
        raise Error(EVERSION)
    if not Cmd.find(cmd):
        raise Error(ECOMMAND)
    try:
        (keyid,serial) = struct.unpack('!6sQ', pkt[2:16])
    except OSError:
        raise Error(EINVAL, 'invalid header format')
    if cmd != Cmd.EmailMe:
        key = key_lookup(keyid)
        h = pkt[-10:]
        if h != _hmac(key, pkt[:-10]):
            raise Error(EHMAC)
    else:
        key = None
    content = pkt[16:-10]
    return (key, serial, cmd, content)
