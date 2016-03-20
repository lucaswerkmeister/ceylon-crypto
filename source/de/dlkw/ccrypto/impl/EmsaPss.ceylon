import de.dlkw.ccrypto.api {
    MessageDigester
}


Byte[8] z8 = [ 0.byte, 0.byte, 0.byte, 0.byte, 0.byte, 0.byte, 0.byte, 0.byte ];

class EmsaPssSign(digest, mgf, saltGenerator, sLen, emBit)
{
    MessageDigester digest;
    digest.reset();
    
    MaskGeneratingFunction mgf;
    
    {Byte*} saltGenerator;
    
    "intended length in octets of the salt"
    Integer sLen;
    
    "maximal bit length of the integer OS2IP..."
    Integer emBit;
    Integer emLen = (emBit - 1) / 8 + 1;
    print("#SemBits: ``emBit``, emLen: ``emLen``");

    Integer hLen => digest.digestLengthOctets;
    assert (emLen >= hLen + sLen + 2);
    print("#SsLen: ``sLen``, hLen: ``hLen``");
    
    shared EmsaPssSign init()
    {
        digest.reset();
        return this;
    }
    
    shared EmsaPssSign update({Byte*} messagePart)
    {
        digest.update(messagePart);
        return this;
    }
    
    shared Byte[] finish()
    {
        value mHash = digest.digest();
        print("#SmHash:");
        hexdump(mHash);

        // DON'T forget to take the sequence() of the take result
        // lest each time you access salt, another value is produced.
        value salt = saltGenerator.take(sLen).sequence();
        print("#Ssalt:");
        hexdump(salt);
        
        value mPrime = z8.chain(mHash).chain(salt);
        print("#SmPrime:");
        hexdump(mPrime);
        
        value h = digest.digest(mPrime);
        print("#Sh:");
        hexdump(h);
        
        value db = { for (i in 0:emLen - sLen - hLen - 2) 0.byte }.chain({1.byte}).chain(salt);
        print("#Sdb:");
        hexdump(db);
        
        value dbMask = mgf.mask(h, emLen - hLen - 1);
        print("#SdbMask:");
        hexdump(dbMask);
        
        value maskedDb = zipPairs(db, dbMask).map((el) => el[0].xor(el[1]));
        print("#SmaskedDb:");
        hexdump(maskedDb.sequence());
        
        Byte  maskUnusedMSBs = #ff.byte.rightLogicalShift(8 * emLen - emBit);
        print("#SmMSB: ``formatInteger(maskUnusedMSBs.unsigned, 16)``");
        assert (exists leftmostOctet = maskedDb.first?.and(maskUnusedMSBs));
        
        return maskedDb.rest.follow(leftmostOctet).chain(h).chain({ #bc.byte }).sequence();
    }
}

class EmsaPssVerify(digest, mgf, sLen, emBits)
{
    MessageDigester digest;
    MaskGeneratingFunction mgf;
    Integer sLen;
    
    Integer emBits;
    Integer emLen = (emBits - 1) / 8 + 1;

    Integer hLen = digest.digestLengthOctets;

    Integer checkBits = 8 * emLen - emBits;
    value checkBitsMask = (1.leftLogicalShift(checkBits) - 1).leftLogicalShift(8 - checkBits).byte;

    shared EmsaPssVerify init()
    {
        digest.reset();
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
        print("#VmaskedDb:");
        hexdump(maskedDb);

        value h = em[emLen - hLen - 1:hLen];
        print("#Vh:");
        hexdump(h);
        
        assert (exists mdb0 = maskedDb[0], mdb0.and(checkBitsMask) == 0.byte);
        
        value dbMask = mgf.mask(h, emLen - hLen - 1);
        print("#VdbMask;");
        hexdump(dbMask);
        
        value db = Array(zipPairs(maskedDb, dbMask).map((el) => el[0].xor(el[1])));
        print("#Vdb");
        hexdump(db);
        
        assert (exists first = db.first);
        db.set(0, first.and(checkBitsMask.not));
        
        assert (db[0:emLen - hLen - sLen - 2].every((b) => b == 0.byte));
        assert (exists b = db[emLen - hLen - sLen - 2], b == 1.byte);
        
        value salt = db.terminal(sLen);
        print("#Vsalt:");
        hexdump(salt);
        
        value mHash = digest.digest();
        print("#VmHash:");
        hexdump(mHash);
        
        value mPrime = z8.chain(mHash).chain(salt);
        print("#VmPrime:");
        hexdump(mPrime.sequence());
        
        value hPrime = digest.digest(mPrime);
        print("#VhPrime:");
        hexdump(hPrime);
        
        return h == hPrime;
    }
}

shared void hexdump({Byte*} b)
{
    print("``[ for (bb in b) formatInteger(bb.unsigned, 16)] ``");
}
