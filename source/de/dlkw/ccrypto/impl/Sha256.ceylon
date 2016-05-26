import de.dlkw.ccrypto.asn1 {
    ObjectIdentifier,
    Asn1Null,
    asn1Null
}
import de.dlkw.ccrypto.api.asn1.pkcs {
    AlgorithmIdentifier,
    mkAlgId = algorithmIdentifier,
    id_sha256
}

"""
   Implementation of the SHA-256 message digest (hash) algorithm
   as given in
   [SHA-256 description](https://web.archive.org/web/20150315061807/http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf)
   
   **Note:** This implementation does not yet support messages longer than `runtime.maxIntegerValue` bits.
   It does not check for exceeding that limit nor for exceeding the maximum message length for SHA-1 (2^64-1 bits).
"""
shared class Sha256()
        extends AbstractDigest(64, 256)
{
    shared actual ObjectIdentifier objectIdentifier => id_sha256;
    shared actual AlgorithmIdentifier<Asn1Null> algorithmIdentifier = mkAlgId(objectIdentifier, asn1Null());
    
    value hInit = Array({ #6a09e667, #bb67ae85, #3c6ef372, #a54ff53a, #510e527f, #9b05688c, #1f83d9ab, #5be0cd19 });

    value k = Array({
        #428a2f98, #71374491, #b5c0fbcf, #e9b5dba5,
        #3956c25b, #59f111f1, #923f82a4, #ab1c5ed5,
        #d807aa98, #12835b01, #243185be, #550c7dc3,
        #72be5d74, #80deb1fe, #9bdc06a7, #c19bf174,
        #e49b69c1, #efbe4786, #0fc19dc6, #240ca1cc,
        #2de92c6f, #4a7484aa, #5cb0a9dc, #76f988da,
        #983e5152, #a831c66d, #b00327c8, #bf597fc7,
        #c6e00bf3, #d5a79147, #06ca6351, #14292967,
        #27b70a85, #2e1b2138, #4d2c6dfc, #53380d13,
        #650a7354, #766a0abb, #81c2c92e, #92722c85,
        #a2bfe8a1, #a81a664b, #c24b8b70, #c76c51a3,
        #d192e819, #d6990624, #f40e3585, #106aa070,
        #19a4c116, #1e376c08, #2748774c, #34b0bcb5,
        #391c0cb3, #4ed8aa4a, #5b9cca4f, #682e6ff3,
        #748f82ee, #78a5636f, #84c87814, #8cc70208,
        #90befffa, #a4506ceb, #bef9a3f7, #c67178f2 });
    
    value hCurrent = Array(hInit);
    
    // FIXME correct this
    shared actual Integer? maxMessageLength = null;

    shared actual Sha256 reset()
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
        assert (exists f0 = hCurrent[5]);
        assert (exists g0 = hCurrent[6]);
        assert (exists h0 = hCurrent[7]);
        
        variable value a = a0;
        variable value b = b0;
        variable value c = c0;
        variable value d = d0;
        variable value e = e0;
        variable value f = f0;
        variable value g = g0;
        variable value h = h0;
        
        value w = Array.ofSize(64, 0);
        for (j in 0:64) {
            assert (exists kJ = k[j]);

            Integer wJ;
            if (j < 16) {
                assert (exists mJ = chunk[j]);
                wJ = mJ;
            }
            else {
                assert (exists wJ2 = w[j - 2]);
                assert (exists wJ7 = w[j - 7]);
                assert (exists wJ15 = w[j - 15]);
                assert (exists wJ16 = w[j - 16]);
                wJ = (sigma1(wJ2) + wJ7 + sigma0(wJ15) + wJ16).and(#ffff_ffff);
            }
            w.set(j, wJ);

            Integer tmp1 = (h + capSigma1(e) + ch(e, f, g) + kJ + wJ).and(#ffff_ffff);
            Integer tmp2 = (capSigma0(a) + maj(a, b, c)).and(#ffff_ffff);

            h = g;
            g = f;
            f = e;
            e = (d + tmp1).and(#ffff_ffff);
            d = c;
            c = b;
            b = a;
            a = (tmp1 + tmp2).and(#ffff_ffff);
        }
        
        hCurrent.set(0, (a0 + a).and(#ffff_ffff));
        hCurrent.set(1, (b0 + b).and(#ffff_ffff));
        hCurrent.set(2, (c0 + c).and(#ffff_ffff));
        hCurrent.set(3, (d0 + d).and(#ffff_ffff));
        hCurrent.set(4, (e0 + e).and(#ffff_ffff));
        hCurrent.set(5, (f0 + f).and(#ffff_ffff));
        hCurrent.set(6, (g0 + g).and(#ffff_ffff));
        hCurrent.set(7, (h0 + h).and(#ffff_ffff));
    }
    
    shared actual Byte[] digest({Byte*} messagePart) => super.finish(messagePart);

    Integer ch(Integer x, Integer y, Integer z)
            => x.and(y).xor(not32(x).and(z));
    
    Integer maj(Integer x, Integer y, Integer z)
            => x.and(y).xor(x.and(z)).xor(y.and(z));
    
    Integer capSigma0(Integer x)
            => rotRight32(x, 2).xor(rotRight32(x, 13)).xor(rotRight32(x, 22));
    
    Integer capSigma1(Integer x)
            => rotRight32(x, 6).xor(rotRight32(x, 11)).xor(rotRight32(x, 25));
    
    Integer sigma0(Integer x)
            => rotRight32(x, 7).xor(rotRight32(x, 18)).xor(x.rightLogicalShift(3));
    
    Integer sigma1(Integer x)
            => rotRight32(x, 17).xor(rotRight32(x, 19)).xor(x.rightLogicalShift(10));
}
