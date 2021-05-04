import threading
import time
import struct

import serial # easy_install pyserial

import sha


# Baud rates linux seems to support:
# 0 50 75 110 134 150 200 300 600 1200 1800 2400 4800 9600 19200 38400 57600 115200 230400 460800 576000 921600 1152000 1500000 3000000...
def test(br):
    ser = serial.Serial("/dev/ttyUSB1", br, timeout=.1)
    try:
        ser.read(1)
    except serial.serialutil.SerialException:
        return False
    finally:
        ser.close()
    return True

# for i in xrange(0, 10000000, 1200):
    # if test(i):
        # print i

class FPGAController(object):
    def __init__(self):
        self.ser = serial.Serial("/dev/ttyUSB1", 115200, timeout=4)

        t = threading.Thread(target=self.read_thread)
        t.setDaemon(True)
        t.start()

        self.last_msg = ''.encode("hex")
        FPGAController.__init__ = None

    def read_thread(self):
        msg = ""
        while True:
            c = self.ser.read(1)
            msg += c
            if msg.endswith("\xde\xad\x43\x29\x87\xbe\xef\xaa"[::-1]):
                s = msg.encode("hex")
                if len(msg) == 32:
                    self.last_msg = msg
                    print "received: %s" % (s,)
                else:
                    print "bad msg:  %s" % (s)

                msg = ""

    def finish_dsha(self, _X, Y, nonce):
        X =  struct.pack(">IIIIIIII", *_X[::-1])[::-1]
        data =  X + Y + nonce + '\x00' * 16
        assert len(data) == 64
        print data.encode("hex")
        self.ser.write(data)

        time.sleep(.1)
        digest = self.last_msg[:32]
        print(digest)
        assert self.last_msg[32] == '\xaa'
        returned_nonce = self.last_msg[33:37]
        assert self.last_msg[37] == '\xaa'
        assert returned_nonce == nonce, (returned_nonce.encode("hex"), nonce.encode("hex"))
        # assert digest == sha.finish_dsha(_X, Y, nonce)
        return digest

    def actually_dsha(self, block_data, nonce):
        #data = block_data + nonce
        #assert len(data) == 64
        #print data.encode("hex")
        data = struct.pack(">IIIIIIII", *[1035495940, 3049640967, 415613342, 2842011426, 3328267282, 3785566386, 1282652657, 896362020][::-1])[::-1]
        #data = data + block_data
        data += '\xb1i\x9d\xec\xed\x86NP\xaf\xc4*\x1c'
        #data += str(nonce)
        data += 'Y\x1f\xbb\xb4'
        data += '\x00' * 16
        self.ser.write(data)
        time.sleep(.1)

        digest = self.last_msg[:32]
        return digest;


    def start_dsha(self, _X, Y):
        X = struct.pack(">IIIIIIII", *_X[::-1])[::-1]
        data =  X + Y + '\x00' * 20
        assert len(data) == 64
        print "sending:  %s" % data.encode("hex")
        self.ser.write(data)

        time.sleep(.1)
        self.last_msg = None

    def winning_nonces_gen(self, _X, Y):
        while True:
            while self.last_msg is None:
                yield None
                time.sleep(.01)
            m = self.last_msg
            self.last_msg = None

            assert m[0] == '\xaa'
            nonce = m[1:5]
            print "raw nonce: %s" % (nonce.encode("hex"),)
            assert m[5] == '\xaa'
            real_digest = sha.finish_dsha(_X, Y, nonce)
            print "gives digest: %s" % (real_digest.encode("hex"),)
            # assert digest == real_digest, (digest.encode("hex"), real_digest.encode("hex"))
            assert real_digest.endswith("\x00\x00")
            yield nonce[::-1]

if __name__ == "__main__":
    c = FPGAController()

    X, Y, nonce = ([1035495940, 3049640967, 415613342, 2842011426, 3328267282, 3785566386, 1282652657, 896362020],'\xb1i\x9d\xec\xed\x86NP\xaf\xc4*\x1c', '\x02|\x95\xb2')

    
    digest = '32e4b6f2825ab10b227532466880f2f658e19d0c2824e069ff3f81b3cc090000'.decode("hex")
    reported_nonce =  'Y\x1f\xbb\xb4'
    _i = struct.unpack("<I", reported_nonce)[0]
    for i in xrange(_i-100, _i+100):
        d = c.finish_dsha(X, Y, struct.pack("<I", i)).encode("hex")
        print(d)
        #if d.endswith("0000"):
            #raise Exception(d)
    
    
    blockRaw = \
        '01000000000000000000000000000000000000000000000000000000000000000000000' \
        '03ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f' \
        '49ffff001d1dac2b7c01010000000100000000000000000000000000000000000000000' \
        '00000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030' \
        '332f4a616e2f32303039204368616e63656c6c6f72206f6e20627266e6b206f66207365' \
        '636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a010000004' \
        '34104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649' \
        'f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000' \
        
    #blockData = int(blockRaw,16)
    done = False
    nonce = '0'.encode()
    target = '0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
    print(c.actually_dsha(target, nonce))
    while not done:
        temp = c.actually_dsha(blockRaw, nonce)
        print (temp)
        if temp == target:
            done = True
            print('Solution found')
        else:
            nonce = str(int(nonce)+1).decode()
            #nonce = '0'.decode()

    # print sha.finish_dsha(X, Y, nonce).encode("hex")
    # print c.finish_dsha(X, Y, nonce).encode("hex")
    c.start_dsha(X, Y)
    for nonce in c.winning_nonces_gen(X, Y):
        print nonce.encode("hex")
