import ceylon.whole {
    Whole,
    zero,
    formatWhole
}
import de.dlkw.ccrypto.api {
    SignatureVerifier,
    RsaPublicKey,
    RsaPrivateKey,
    RsaExponentPrivateKey,
    RsaCrtPrivateKey,
    MessageDigester,
    Signer
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

shared class RsaSsaPssSign(key, outerHash, mgf, saltGenerator, saltLength)
        satisfies Signer<RsaPrivateKey>
{
    variable RsaPrivateKey key;
    MessageDigester outerHash;
    MaskGeneratingFunction mgf;
    {Byte*} saltGenerator;
    Integer saltLength;
    
    value emsa = EmsaPssSign(outerHash, mgf, saltGenerator, saltLength, key.bitLength - 1);
    
    shared actual void init(RsaPrivateKey key)
    {
        this.key = key;
        reset();
    }
    
    shared actual void reset()
    {
        outerHash.reset();
        emsa.init();
    }
    
    shared actual RsaSsaPssSign update({Byte*} messagePart)
    {
        emsa.update(messagePart);
        return this;
    }
    
    shared actual Byte[] sign({Byte*} messagePart)
    {
        value em = emsa.update(messagePart).finish();
        print("em: ``em.size``");
        hexdump(em);
        
        value w = os2ip(em);
        value wEnc = Rsa().rsaSp1(key, w);
        print("w: ``formatWhole(w, 16)``");
        print("wEnc: ``formatWhole(wEnc, 16)``");
        
        return i2osp(wEnc, key.octetLength);
    }
}

shared class RsaSsaPssVerify(key, outerHash, mgf, saltLength)
        satisfies SignatureVerifier<RsaPublicKey>
{
    variable RsaPublicKey key;
    MessageDigester outerHash;
    MaskGeneratingFunction mgf;
    Integer saltLength;
    
    value emLen = (key.bitLength - 2) / 8 + 1;
    
    
    value emsa = EmsaPssVerify(outerHash, mgf, saltLength, key.bitLength - 1);
    
    shared actual void init(RsaPublicKey key)
    {
        this.key = key;
        reset();
    }
    
    shared actual void reset()
    {
        outerHash.reset();
        emsa.init();
    }

    shared actual RsaSsaPssVerify update({Byte*} messagePart)
    {
        emsa.update(messagePart);
        return this;
    }
    
    shared actual Boolean verify(Byte[] signature, {Byte*} messagePart)
    {
        value s = os2ip(signature);

        value m = Rsa().rsaVp1(key, s);
        print("verify m: ``formatWhole(m, 16)``");

        value em = i2osp(m, emLen);
        print("verify em:");
        hexdump(em);

        return emsa.update(messagePart).verify(em);
    }
}

shared RsaSsaPssSign sha1WithRsaAndMgf1Sha1Signer(RsaPrivateKey key, {Byte*} saltGenerator, Integer saltLength)
        => RsaSsaPssSign(key, createSha1(), MGF1(createSha1()), saltGenerator, saltLength);

shared RsaSsaPssVerify sha1WithRsaAndMgf1Sha1Verifier(RsaPublicKey key, Integer saltLength)
        => RsaSsaPssVerify(key, createSha1(), MGF1(createSha1()), saltLength);

shared RsaSsaPssSign sha256WithRsaAndMgf1Sha256Signer(RsaPrivateKey key, {Byte*} saltGenerator, Integer saltLength)
        => RsaSsaPssSign(key, createSha256(), MGF1(createSha256()), saltGenerator, saltLength);

shared RsaSsaPssVerify sha256WithRsaAndMgf1Sha256Verifier(RsaPublicKey key, Integer saltLength)
        => RsaSsaPssVerify(key, createSha256(), MGF1(createSha256()), saltLength);
