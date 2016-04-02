import ceylon.buffer.charset {
    ascii
}
import ceylon.interop.java {
    createJavaByteArray
}
import ceylon.random {
    DefaultRandom
}
import ceylon.test {
    test
}
import ceylon.time {
    systemTime
}

import de.dlkw.ccrypto.api {
    MessageDigester
}
import de.dlkw.ccrypto.impl {
    Sha256,
    Sha1
}

import java.security {
    MessageDigest
}

test
void run() {
    List<Byte> bb = ascii.encode("Franz jagt im komplett verwahrlosten Taxi quer durch Bayern");
    value expected = [#d3.byte, #2b.byte, #56.byte, #8c.byte, #d1.byte, #b9.byte, #6d.byte, #45.byte, #9e.byte, #72.byte, #91.byte, #eb.byte, #f4.byte, #b2.byte, #5d.byte, #0.byte, #7f.byte, #27.byte, #5c.byte, #9f.byte, #13.byte, #14.byte, #9b.byte, #ee.byte, #b7.byte, #82.byte, #fa.byte, #c0.byte, #71.byte, #66.byte, #13.byte, #f8.byte];
    value sha256 = Sha256();
    value digest = sha256.digest(bb);
    print(digest.collect((b)=>formatInteger(b.unsigned, 16)));
    
    value x = MessageDigest.getInstance("SHA-256");
    Array<Byte> d = x.digest().byteArray;
    assert (expected.sequence() == digest);
    
    Sha256Tester tester = Sha256Tester();
    
    tester.cmpWithJava{};
    
    value rnd = DefaultRandom();
    
    value t = systemTime.instant();
    for (l in 0..2049) {
        for (n in 0:100) {
            value input = Array(rnd.bytes().take(l));
            tester.cmpWithJava(input);
        }
    }
    print("dur: ``systemTime.instant().durationFrom(t)``");
}

test
void run_1() {
    List<Byte> bb = ascii.encode("The quick brown fox jumps over the lazy dog");
    value expected = [#2f.byte, #d4.byte, #e1.byte, #c6.byte, #7a.byte, #2d.byte, #28.byte, #fc.byte, #ed.byte, #84.byte, #9e.byte, #e1.byte, #bb.byte, #76.byte, #e7.byte, #39.byte, #1b.byte, #93.byte, #eb.byte, #12.byte];
    value sha1 = Sha1();
    value digest = sha1.digest(bb);
    Sha1Tester().cmpWithJava(bb);
    assert(expected == digest);
}

test
void testDifferentPartSizesSha1()
{
    differentPartSizes(Sha1(), MessageDigest.getInstance("SHA-1"));
}

test
void testDifferentPartSizesSha256()
{
    differentPartSizes(Sha256(), MessageDigest.getInstance("SHA-256"));
}

void differentPartSizes(MessageDigester dig1, MessageDigest javaDig)
{
    value rnd = DefaultRandom();
    
    value stock = Array<Byte>.ofSize(1100, 0.byte);
    for (i in 0:1100) {
        stock.set(i, rnd.nextByte());
    }
    
    for (partSize in 1..520) {
        variable Integer from = 0;
        variable Integer to = from + partSize;
        
        while (to < 600) {
            dig1.update(stock[from .. to - 1]);
            from = to;
            to = from + partSize;
        }
        value digest = dig1.digest(stock[from .. 599]);
        
        value digest2 = dig1.digest(stock[...599]);
        assert (digest == digest2);
        
        value refDigest = javaDig.digest(createJavaByteArray(stock[...599])).byteArray;
        assert (digest == refDigest);
    }
}

class Sha256Tester()
{
    value cSha256 = Sha256();
    value jSha256 = MessageDigest.getInstance("SHA-256");

    shared void cmpWithJava({Byte*}bytes)
    {
        value cResult = cSha256.digest(bytes);
        value jResult = jSha256.digest(createJavaByteArray(bytes)).byteArray;
        
        assert (cResult.size == jResult.size);
        assert (cResult.startsWith(jResult));
    }
}


class Sha1Tester()
{
    value cSha1 = Sha1();
    value jSha1 = MessageDigest.getInstance("SHA-1");
    
    shared void cmpWithJava({Byte*}bytes)
    {
        value cResult = cSha1.digest(bytes);
        value jResult = jSha1.digest(createJavaByteArray(bytes)).byteArray;
        
        assert (cResult.size == jResult.size);
        assert (cResult.startsWith(jResult));
    }
}
