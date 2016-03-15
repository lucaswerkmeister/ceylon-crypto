import ceylon.whole {
    Whole,
    zero,
    formatWhole
}
class Rsa()
{
    shared Whole rsaSp1(RsaPrivateKey key, Whole message)
    {
        assert (zero <= message < key.modulus);
        
        switch (key)
        case (is RsaExponentPrivateKey) {
            return message.moduloPower(key.exponent, key.modulus);
        }
        case (is RsaCrtPrivateKey) {
            value m = message;
            value s1 = m.moduloPower(key.dP, key.p);
            value s2 = m.moduloPower(key.dQ, key.q);
            
            // more than two prime factors of the modulus is not supported
            
            value h = ((s1 - s2) * key.qInv).modulo(key.p);
            return s2 + key.q * h;
        }
    }
    
    shared Whole rsaVp1(RsaPublicKey key, Whole signature)
    {
        assert (zero <= signature < key.modulus);
        return signature.moduloPower(key.exponent, key.modulus);
    }
}

shared class RsaSsaPssSign(RsaPrivateKey key, saltGenerator)
{
    {Byte*} saltGenerator;
    
    Digest outerHash = createSha1();
    value emsa = EmsaPssSign(outerHash, MGF1(createSha1()), saltGenerator, outerHash.digestLengthOctets, key.bitLength - 1);
    
    shared RsaSsaPssSign update({Byte*} messagePart)
    {
        emsa.update(messagePart);
        return this;
    }
    
    shared Byte[] finish()
    {
        value em = emsa.finish();
        print(em.size);
        hexdump(em);
        
        value w = os2ip(em);
        value wEnc = Rsa().rsaSp1(key, w);
        print(formatWhole(w, 16));
        print(formatWhole(wEnc, 16));
        
        return i2osp(wEnc, key.octetLength);
    }
}

shared class RsaSsaPssVerify(RsaPublicKey key)
{
    value emLen = (key.bitLength - 2) / 8 + 1;
    
    Digest outerHash = createSha1();
    value emsa = EmsaPssVerify(outerHash, MGF1(createSha1()), outerHash.digestLengthOctets, key.bitLength - 1);

    shared RsaSsaPssVerify update({Byte*} messagePart)
    {
        emsa.update(messagePart);
        return this;
    }
    
    shared Boolean verify(Byte[] signature)
    {
        value s = os2ip(signature);

        value m = Rsa().rsaVp1(key, s);
        print(formatWhole(m, 16));

        value em = i2osp(m, emLen);
        hexdump(em);

        return emsa.verify(em);
    }
}