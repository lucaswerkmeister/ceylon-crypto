import ceylon.buffer.charset {
    ascii
}
import de.dlkw.ccrypto {
    createSha256,
    createSha1
}
import java.security { MessageDigest }
import ceylon.interop.java {
    createJavaByteArray
}
import ceylon.random {
    Random,
    DefaultRandom
}
import ceylon.time {
    Instant,
    systemTime,
    Duration
}

"Run the module `algotest`."
shared void run() {
    List<Byte> bb = ascii.encode("Franz jagt im komplett verwahrlosten Taxi quer durch Bayern");
    value expected = [#d3.byte, #2b.byte, #56.byte, #8c.byte, #d1.byte, #b9.byte, #6d.byte, #45.byte, #9e.byte, #72.byte, #91.byte, #eb.byte, #f4.byte, #b2.byte, #5d.byte, #0.byte, #7f.byte, #27.byte, #5c.byte, #9f.byte, #13.byte, #14.byte, #9b.byte, #ee.byte, #b7.byte, #82.byte, #fa.byte, #c0.byte, #71.byte, #66.byte, #13.byte, #f8.byte];
    value sha256 = createSha256();
    value digest = sha256.updateFinish(bb);
    print(digest.collect((b)=>formatInteger(b.unsigned, 16)));
    
    value x = MessageDigest.getInstance("SHA-256");
    Array<Byte> d = x.digest().byteArray;
    print(d.collect((e)=>formatInteger(e.unsigned, 16)));
    
    Sha256Tester tester = Sha256Tester();
    
    tester.cmpWithJava{};
    
    value rnd = DefaultRandom();
    
    value t = systemTime.instant();
    for (l in 0..2049) {
    //    print(l);
        for (n in 0:100) {
            value input = Array(rnd.bytes().take(l));
            tester.cmpWithJava(input);
        }
    }
    print("dur: ``systemTime.instant().durationFrom(t)``");
}

shared void run_1() {
    List<Byte> bb = ascii.encode("The quick brown fox jumps over the lazy cog");
    value expected = [#2f.byte, #d4.byte, #e1.byte, #c6.byte, #7a.byte, #2d.byte, #28.byte, #fc.byte, #ed.byte, #84.byte, #9e.byte, #e1.byte, #bb.byte, #76.byte, #e7.byte, #39.byte, #1b.byte, #93.byte, #eb.byte, #12.byte];
    value sha1 = createSha1();
    value digest = sha1.updateFinish(bb);
    print(digest.collect((b)=>formatInteger(b.unsigned, 16)));
}

class Sha256Tester()
{
    value cSha256 = createSha256();
    value jSha256 = MessageDigest.getInstance("SHA-256");

    shared void cmpWithJava({Byte*}bytes)
    {
        //value cResult = cSha256.updateFinish(bytes);
        value jResult = jSha256.digest(createJavaByteArray(bytes)).byteArray;
        
        //assert (cResult.size == jResult.size);
        //assert (cResult.startsWith(jResult));
    }
}


class Sha1Tester()
{
    value cSha1 = createSha1();
    value jSha1 = MessageDigest.getInstance("SHA-1");
    
    shared void cmpWithJava({Byte*}bytes)
    {
        value cResult = cSha1.updateFinish(bytes);
        value jResult = jSha1.digest(createJavaByteArray(bytes)).byteArray;
        
        assert (cResult.size == jResult.size);
        assert (cResult.startsWith(jResult));
    }
}
