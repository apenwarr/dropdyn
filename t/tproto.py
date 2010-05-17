from wvtest import *
import proto

@wvtest
def proto_test():
    WVPASSEQ(proto.EPERM, 0x30)
    WVPASS(proto._keyid('foo'))
    h1 = proto._hmac('foo', 'content')
    h1b = proto._hmac('foo', 'content2')
    h2 = proto._hmac('boo'*30, 'content')
    WVPASS(h1)
    WVPASS(h1b)
    WVPASS(h2)
    WVPASSNE(h1, h1b)
    WVPASSNE(h1, h2)
    WVPASSNE(h1b, h2)

    pkt = proto.pack('foo', 23, proto.Cmd.KeyGen, 'chunky')
    def kl(kid):
        WVPASSEQ(kid, proto._keyid('foo'))
        return 'foo'
    (key,serial,cmd,content) = proto.unpack(pkt, kl)
    WVPASSEQ(key, 'foo')
    WVPASSEQ(serial, 23)
    WVPASSEQ(cmd, proto.Cmd.KeyGen)
    WVPASSEQ(content, 'chunky')

    pkt = pkt[:-5] + chr(ord(pkt[-5]) ^ 1) + pkt[:-4]
    WVEXCEPT(proto.Error, proto.unpack, pkt, kl)
