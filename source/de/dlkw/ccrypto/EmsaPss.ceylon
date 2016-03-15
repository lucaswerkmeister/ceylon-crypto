

Byte[8] z8 = [ 0.byte, 0.byte, 0.byte, 0.byte, 0.byte, 0.byte, 0.byte, 0.byte ];

class EmsaPssSign(digest, mgf, saltGenerator, sLen, emBit)
{
    Digest digest;
    digest.init();
    
    MaskGeneratingFunction mgf;
    
    {Byte*} saltGenerator;
    
    "intended length in octets of the salt"
    Integer sLen;
    
    "maximal bit length of the integer OS2IP..."
    Integer emBit;
    Integer emLen = (emBit - 1) / 8 + 1;
    print("emBits: ``emBit``, emLen: ``emLen``");

    Integer hLen => digest.digestLengthOctets;
    assert (emLen >= hLen + sLen + 2);
    print("sLen: ``sLen``, hLen: ``hLen``");
    
    shared EmsaPssSign init()
    {
        digest.init();
        return this;
    }
    
    shared EmsaPssSign update({Byte*} messagePart)
    {
        hexdump(messagePart.sequence());
        digest.update(messagePart);
        return this;
    }
    
    shared Byte[] finish()
    {
        value mHash = digest.finish();
        hexdump(mHash);

        value salt = saltGenerator.take(sLen);
        
        value mPrime = z8.chain(mHash).chain(salt);
        hexdump(mPrime.sequence());
        
        value h = digest.updateFinish(mPrime);
        hexdump(h);
        
        value db = { for (i in 0:emLen - sLen - hLen - 2) 0.byte }.chain({1.byte}).chain(salt);
        hexdump(db.sequence());
        
        value dbMask = mgf.mask(h, emLen - hLen - 1);
        hexdump(dbMask);
        
        value maskedDb = zipPairs(db, dbMask).map((el) => el[0].xor(el[1]));
        hexdump(maskedDb.sequence());
        
        Byte  maskUnusedMSBs = #ff.byte.rightLogicalShift(8 * emLen - emBit);
        print("mMSB: ``formatInteger(maskUnusedMSBs.unsigned, 16)``");
        assert (exists leftmostOctet = maskedDb.first?.and(maskUnusedMSBs));
        
        return maskedDb.rest.follow(leftmostOctet).chain(h).chain({ #bc.byte }).sequence();
    }
}

class EmsaPssVerify(digest, mgf, sLen, emBits)
{
    Digest digest;
    MaskGeneratingFunction mgf;
    Integer sLen;
    
    Integer emBits;
    Integer emLen = (emBits - 1) / 8 + 1;

    Integer hLen = digest.digestLengthOctets;

    Integer checkBits = 8 * emLen - emBits;
    value checkBitsMask = (1.leftLogicalShift(checkBits) - 1).leftLogicalShift(8 - checkBits).byte;

    shared EmsaPssVerify init()
    {
        digest.init();
        return this;
    }
    
    shared EmsaPssVerify update({Byte*} messagePart)
    {
        digest.update(messagePart);
        return this;
    }
    
    shared Boolean verify(Byte[] em)
    {
        assert (em.size == emLen);
        assert (exists bc = em.last, bc == #bc.byte);
        
        value maskedDb = em[0:emLen - hLen - 1];
        hexdump(maskedDb);

        value h = em[emLen - hLen - 1:hLen];
        hexdump(h);
        
        assert (exists mdb0 = maskedDb[0], mdb0.and(checkBitsMask) == 0.byte);
        
        value dbMask = mgf.mask(h, emLen - hLen - 1);
        hexdump(dbMask);
        
        value db = Array(zipPairs(maskedDb, dbMask).map((el) => el[0].xor(el[1])));
        
        assert (exists first = db.first);
        db.set(0, first.and(checkBitsMask.not));
        
        assert (db[0:emLen - hLen - sLen - 2].every((b) => b == 0.byte));
        assert (exists b = db[emLen - hLen - sLen - 2], b == 1.byte);
        
        value salt = db.terminal(sLen);
        
        value mHash = digest.finish();
        hexdump(mHash);
        
        value mPrime = z8.chain(mHash).chain(salt);
        hexdump(mPrime.sequence());
        
        value hPrime = digest.updateFinish(mPrime);
        hexdump(hPrime);
        
        return h == hPrime;
    }
}

shared void hexdump(Byte[] b)
{
    print("``[ for (bb in b) formatInteger(bb.unsigned, 16)] ``");
}
