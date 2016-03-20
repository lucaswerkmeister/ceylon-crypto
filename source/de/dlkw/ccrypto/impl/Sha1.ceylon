
"""
   Implementation of the SHA-1 message digest (hash) algorithm
   implemented from the pseudocode in the [Wikipedia article](https://en.wikipedia.org/wiki/SHA-1)
"""
shared class Sha1()
        extends AbstractDigest(64, 160)
{
    value hInit = Array({ #67452301, #efcdab89, #98badcfe, #10325476, #c3d2e1f0 });

    value hCurrent = Array(hInit);
    
    // FIXME correct this
    shared actual Integer? maxMessageLength = null;

    shared actual Sha1 reset()
    {
        super.reset();
        hInit.copyTo(hCurrent);
        return this;
    }

    shared actual void padLast()
    {
        Integer msbLen = numBytesUsed.rightLogicalShift(29).and(#ffff_ffff);
        Integer lsbLen = numBytesUsed.leftLogicalShift(3).and(#ffff_ffff);
        
        update({#80.byte});
        Integer missing = 56 - numBytesUsed % blockSize;
        Integer miss = missing < 0 then missing + blockSize else missing;
        
        update(Array.ofSize(miss, 0.byte));
        update(toBytes(msbLen));
        update(toBytes(lsbLen));
    }
    
    shared actual Byte[] finishedResult => concatenate(for (v in hCurrent) toBytes(v));

    // processes exactly one block (64 bytes)
    shared actual void processBlock({Byte*} msg)
    {
        value chunk = Array.ofSize(16, 0);
        value iterator = msg.iterator();
        for (i in 0:16) {
            assert (is Byte b3 = iterator.next());
            assert (is Byte b2 = iterator.next());
            assert (is Byte b1 = iterator.next());
            assert (is Byte b0 = iterator.next());
            chunk.set(i, b3.unsigned.leftLogicalShift(24)
                    .or(b2.unsigned.leftLogicalShift(16))
                    .or(b1.unsigned.leftLogicalShift(8))
                    .or(b0.unsigned));
        }
        assert (is Finished el = iterator.next());
        processIntegerChunk(chunk);
    }
    
    // processes exactly one block (eight 32-bit integers)
    shared void processIntegerChunk(List<Integer> chunk)
    {
        assert (exists a0 = hCurrent[0]);
        assert (exists b0 = hCurrent[1]);
        assert (exists c0 = hCurrent[2]);
        assert (exists d0 = hCurrent[3]);
        assert (exists e0 = hCurrent[4]);
        
        variable value a = a0;
        variable value b = b0;
        variable value c = c0;
        variable value d = d0;
        variable value e = e0;
        
        value w = Array.ofSize(80, 0);
        for (j in 0:80) {
            Integer wJ;
            if (j < 16) {
                assert (exists mJ = chunk[j]);
                wJ = mJ;
            }
            else {
                assert (exists wJ3 = w[j - 3]);
                assert (exists wJ8 = w[j - 8]);
                assert (exists wJ14 = w[j - 14]);
                assert (exists wJ16 = w[j - 16]);
                wJ = rotLeft32(wJ3.xor(wJ8).xor(wJ14).xor(wJ16), 1);
            }
            w.set(j, wJ);

            Integer f;
            Integer k;
            if (j < 20) {
                f = b.and(c).or(not32(b).and(d));
                k = #5a827999;
            }
            else if (j < 40) {
                f = b.xor(c).xor(d);
                k = #6ed9eba1;
            }
            else if (j < 60) {
                f = b.and(c).or(b.and(d)).or(c.and(d));
                k = #8f1bbcdc;
            }
            else {
                f = b.xor(c).xor(d);
                k = #ca62c1d6;
            }

            Integer tmp = (rotLeft32(a, 5) + f + e + k + wJ).and(#ffff_ffff);

            e = d;
            d = c;
            c = rotLeft32(b, 30);
            b = a;
            a = tmp;
        }
        
        hCurrent.set(0, (a0 + a).and(#ffff_ffff));
        hCurrent.set(1, (b0 + b).and(#ffff_ffff));
        hCurrent.set(2, (c0 + c).and(#ffff_ffff));
        hCurrent.set(3, (d0 + d).and(#ffff_ffff));
        hCurrent.set(4, (e0 + e).and(#ffff_ffff));
    }

    shared actual Byte[] digest({Byte*} messagePart) => finish(messagePart);
}

Integer not32(Integer x) => x.not.and(#ffff_ffff);

Integer rotRight32(Integer num, Integer rot)
{
    Integer num32 = num.and(#ffff_ffff);
    return num32.rightLogicalShift(rot).or(num32.leftLogicalShift(32 - rot).and(#ffff_ffff));
}

Integer rotLeft32(Integer num, Integer rot)
{
    Integer num32 = num.and(#ffff_ffff);
    return num32.leftLogicalShift(rot).or(num32.rightLogicalShift(32 - rot).and(#ffff_ffff));
}

shared void test2b1()
{
    value m = [#61626380, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, #18];
    value sha1 = Sha1();
    print("3 byte integer primitive");
    sha1.processIntegerChunk(m);
    print(sha1.finishedResult.collect((b)=>formatInteger(b.unsigned, 16)));
    
    print("ext use");
    sha1.reset();
    sha1.update({#61.byte, #62.byte, #63.byte});
    print(sha1.finish().collect((b)=>formatInteger(b.unsigned, 16)));
    
    value m2_0 = [
        #61626364, #62636465, #63646566, #64656667, #65666768, #66676869, #6768696a, #68696a6b,
        #696a6b6c, #6a6b6c6d, #6b6c6d6e, #6c6d6e6f, #6d6e6f70, #6e6f7071, #80000000, #00000000
    ];
    value m2_1 = [
        #00000000, #00000000, #00000000, #00000000, #00000000, #00000000, #00000000, #00000000,
        #00000000, #00000000, #00000000, #00000000, #00000000, #00000000, #00000000, #000001c0
    ];
        
    print("56 byte integer primitive");
    sha1.processIntegerChunk(m2_0);
    sha1.processIntegerChunk(m2_1);
    print(sha1.finishedResult.collect((b)=>formatInteger(b.unsigned, 16)));
    
    print("ext use");
    sha1.reset();
    sha1.update({#61.byte, #62.byte, #63.byte, #64.byte});
    sha1.update({#62.byte, #63.byte, #64.byte, #65.byte});
    sha1.update({#63.byte, #64.byte, #65.byte, #66.byte});
    sha1.update({#64.byte, #65.byte, #66.byte, #67.byte});
    sha1.update({#65.byte, #66.byte, #67.byte, #68.byte});
    sha1.update({#66.byte, #67.byte, #68.byte, #69.byte});
    sha1.update({#67.byte, #68.byte, #69.byte, #6a.byte});
    sha1.update({#68.byte, #69.byte, #6a.byte, #6b.byte});
    sha1.update({#69.byte, #6a.byte, #6b.byte, #6c.byte});
    sha1.update({#6a.byte, #6b.byte, #6c.byte, #6d.byte});
    sha1.update({#6b.byte, #6c.byte, #6d.byte, #6e.byte});
    sha1.update({#6c.byte, #6d.byte, #6e.byte, #6f.byte});
    sha1.update({#6d.byte, #6e.byte, #6f.byte, #70.byte});
    sha1.update({#6e.byte, #6f.byte, #70.byte, #71.byte});
    print(sha1.finish().collect((b)=>formatInteger(b.unsigned, 16)));
    
    print("3 byte message internal");
    sha1.processBlock({#61.byte, #62.byte, #63.byte, #80.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #18.byte});
    print(sha1.finishedResult.collect((b)=>formatInteger(b.unsigned, 16)));
    
    print("56 byte message internal");
    sha1.reset();
    sha1.processBlock({#61.byte, #62.byte, #63.byte, #64.byte
    ,#62.byte, #63.byte, #64.byte, #65.byte
    ,#63.byte, #64.byte, #65.byte, #66.byte
    ,#64.byte, #65.byte, #66.byte, #67.byte
    ,#65.byte, #66.byte, #67.byte, #68.byte
    ,#66.byte, #67.byte, #68.byte, #69.byte
    ,#67.byte, #68.byte, #69.byte, #6a.byte
    ,#68.byte, #69.byte, #6a.byte, #6b.byte
    ,#69.byte, #6a.byte, #6b.byte, #6c.byte
    ,#6a.byte, #6b.byte, #6c.byte, #6d.byte
    ,#6b.byte, #6c.byte, #6d.byte, #6e.byte
    ,#6c.byte, #6d.byte, #6e.byte, #6f.byte
    ,#6d.byte, #6e.byte, #6f.byte, #70.byte
    ,#6e.byte, #6f.byte, #70.byte, #71.byte
    ,#80.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte});
    sha1.processBlock({
     #00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #00.byte, #00.byte
    ,#00.byte, #00.byte, #01.byte, #c0.byte});
     print(sha1.finishedResult.collect((b)=>formatInteger(b.unsigned, 16)));
}

shared void test2_1()
{
//    da39a3ee5e6b4b0d3255bfef95601890afd80709
    value sha1 = createSha1();
    print(sha1.digest().collect((b)=>formatInteger(b.unsigned, 16)));
}