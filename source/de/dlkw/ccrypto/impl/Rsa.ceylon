import ceylon.whole {
    Whole,
    zero
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
        satisfies Signer
{
    variable RsaPrivateKey key;
    MessageDigester outerHash;
    MaskGeneratingFunction mgf;
    {Byte*} saltGenerator;
    Integer saltLength;
    
    value emsa = EmsaPssSign(outerHash, mgf, saltGenerator, saltLength, key.bitLength - 1);

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
        
        value w = os2ip(em);
        value wEnc = Rsa().rsaSp1(key, w);
        
        return i2osp(wEnc, key.octetLength);
    }
}

shared class RsaSsaPssVerify(key, outerHash, mgf, saltLength)
        satisfies SignatureVerifier
{
    variable RsaPublicKey key;
    MessageDigester outerHash;
    MaskGeneratingFunction mgf;
    Integer saltLength;
    
    value emLen = (key.bitLength - 2) / 8 + 1;

    value emsa = EmsaPssVerify(outerHash, mgf, saltLength, key.bitLength - 1);

    shared actual void reset()
    {
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

        value em = i2osp(m, emLen);

        return emsa.update(messagePart).verify(em) == consistent;
    }
}

shared RsaSsaPssSign sha1WithRsaAndMgf1Sha1Signer(RsaPrivateKey key, {Byte*} saltGenerator, Integer saltLength)
        => RsaSsaPssSign(key, Sha1(), MGF1(Sha1()), saltGenerator, saltLength);

shared RsaSsaPssVerify sha1WithRsaAndMgf1Sha1Verifier(RsaPublicKey key, Integer saltLength)
        => RsaSsaPssVerify(key, Sha1(), MGF1(Sha1()), saltLength);

shared RsaSsaPssSign sha256WithRsaAndMgf1Sha256Signer(RsaPrivateKey key, {Byte*} saltGenerator, Integer saltLength)
        => RsaSsaPssSign(key, Sha256(), MGF1(Sha256()), saltGenerator, saltLength);

shared RsaSsaPssVerify sha256WithRsaAndMgf1Sha256Verifier(RsaPublicKey key, Integer saltLength)
        => RsaSsaPssVerify(key, Sha256(), MGF1(Sha256()), saltLength);

shared class RsaSsaPkcs15Sign(key, digester)
        satisfies Signer
{
    variable RsaPrivateKey key;
    MessageDigester digester;
    
    value emsa = EmsaPkcs1_v1_5(digester, key.octetLength);

    shared actual void reset()
    {
        emsa.init(key.octetLength);
    }
    
    shared actual RsaSsaPkcs15Sign update({Byte*} messagePart)
    {
        emsa.update(messagePart);
        return this;
    }
    
    shared actual Byte[] sign({Byte*} messagePart)
    {
        value em = emsa.update(messagePart).finish();
        
        value m = os2ip(em);
        value s = Rsa().rsaSp1(key, m);
        
        return i2osp(s, key.octetLength);
    }
}

shared class RsaSsaPkcs15Verify(key, digester)
        satisfies SignatureVerifier
{
    variable RsaPublicKey key;
    MessageDigester digester;

    value emsa = EmsaPkcs1_v1_5(digester, key.octetLength);

    shared actual void reset()
    {
        emsa.init(key.octetLength);
    }
    
    shared actual RsaSsaPkcs15Verify update({Byte*} messagePart)
    {
        emsa.update(messagePart);
        return this;
    }
    
    shared actual Boolean verify(Byte[] signature, {Byte*} messagePart)
    {
        value s = os2ip(signature);
        
        value m = Rsa().rsaVp1(key, s);
        
        value em = i2osp(m, key.octetLength);
        
        value emPrime = emsa.update(messagePart).finish();
        
        return em == emPrime;
    }
}

shared RsaSsaPkcs15Sign sha1WithRsaSigner(RsaPrivateKey key)
        => RsaSsaPkcs15Sign(key, Sha1());

shared RsaSsaPkcs15Verify sha1WithRsaVerifier(RsaPublicKey key)
        => RsaSsaPkcs15Verify(key, Sha1());

shared RsaSsaPkcs15Sign sha256WithRsaSigner(RsaPrivateKey key)
        => RsaSsaPkcs15Sign(key, Sha256());

shared RsaSsaPkcs15Verify sha256WithRsaVerifier(RsaPublicKey key)
        => RsaSsaPkcs15Verify(key, Sha256());
