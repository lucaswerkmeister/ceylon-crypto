import ceylon.interop.java {
    createJavaByteArray
}
import ceylon.test {
    test
}
import ceylon.whole {
    parseWhole
}

import de.dlkw.ccrypto.api {
    Signer,
    RsaPrivateKey
}
import de.dlkw.ccrypto.impl {
    os2ip,
    RsaExponentPrivateKeyImpl,
    RsaSsaPkcs15Sign,
    Sha1,
    hexdump,
    RsaSsaPkcs15Verify,
    RsaPublicKeyImpl
}

import java.security {
    Signature,
    KeyPairGenerator
}
import java.security.interfaces {
    JRSAPrivateKey=RSAPrivateKey,
    JRSAPublicKey=RSAPublicKey
}

Byte[] conv(String s) {
    value pieces = s.normalized.split((c) => c.whitespace);
    print(":: ``pieces``");
    value c = [ for (b in pieces) parseInteger(b, 16)?.byte ];
    assert (c.every((el) => el exists));
    return c.coalesced.sequence();
}

String dS = "82 B1 5C 93 F2 E2 5B D7 5E 08 61 CC 1A B1 0D 66 D2 89 AB 84 38 9B E9 60 B7 EA C1 8B 7B 06 B6 D2 B1 25 C2 2D AA 59 DB CB 32 22 92 74 93 72 68 9A 04 70 21 BB CD A2 D4 D1 D2 8B E2 97 9C 0A 40 76 21 33 43 7F 72 95 A8 17 3D 1B 62 E1 BE CA 8C 5F 9B 3F 34 15 4D 42 B7 DD D6 81 2B 4A EE 2A F3 DC 80 B7 31 80 D3 22 6E 19 C9 01 21 74 21 75 DE F6 C1 E8 0C 0A C7 6B 15 49 9B 49 C0 26 61 46 D6 21";
String nS = "B6 DE 72 A7 92 E5 7C 11 96 77 C8 C1 82 2A 4D FB B1 57 51 C9 90 16 0C 60 AE F6 A3 CE 87 30 3A 61 7C 31 62 47 B6 52 0A 47 FB 70 BC D8 2A 73 9C 11 84 82 8D AB 52 9F 48 4A CF 71 0B F7 8D B6 69 CD 40 49 FB 62 E0 FF 17 25 05 1E E5 66 3D 9D F8 31 1F EE 3A CA 26 7A 16 B7 D0 AD B3 21 9E 25 8A 36 9E 06 D8 1D 67 FE D9 E2 00 00 7A EC 04 27 C1 0A A5 13 D5 92 90 16 6C 22 52 9A CE FC 17 BB 6B 93";
String mS = "11 11 12 22 99";
String s = "15 8D 86 24 BE E4 F1 FF 58 40 16 32 23 20 E1 9A 64 94 E2 3C 95 90 9B DE B8 5F 5E 99 9D 36 73 24 4A 8C 39 41 AD FC 50 C4 BE AE 10 F6 2F 68 BB AD 64 79 7B 66 E9 1B C6 17 62 63 C6 75 5B 83 1F 42 65 C9 5A 65 91 2B FE D8 DE 39 8C 78 E9 A8 3E 34 A2 ED 0E 34 E3 9B D9 93 A9 1B 08 35 B2 18 9E 44 4F 53 45 A9 0E D5 BD 47 6C 6F 5B E0 8D D1 B3 BE 69 F9 FF 84 2D D5 14 2C D2 9E C4 54 10 15 89 A4";

test
shared void test01()
{
    value message = conv(mS);
    hexdump(message);
    value d = conv(dS);
    hexdump(d);
    value n = conv(nS);
    hexdump(n);
    
    value privKey = RsaExponentPrivateKeyImpl(os2ip(d), os2ip(n));
    Signer<RsaPrivateKey> rsaSig = RsaSsaPkcs15Sign(privKey, Sha1());
    value sig = rsaSig.update(message).sign();
    hexdump(sig);
    
    value jSig = Signature.getInstance("sha1WithRsa");
    
    value jGen = KeyPairGenerator.getInstance("RSA");
    jGen.initialize(4095);
    value jKP = jGen.generateKeyPair();
    value jKey = jKP.private;
    assert (is JRSAPrivateKey jKey);
    jSig.initSign(jKey);
    jSig.update(createJavaByteArray(message));
    value ss = jSig.sign().array.map((b) => b.byteValue()).sequence();
    print("jsig");
    hexdump(ss);
    
    value jd = parseWhole(jKey.privateExponent.string);
    value jn = parseWhole(jKey.modulus.string);
    value jPub = jKP.public;
    assert (is JRSAPublicKey jPub);
    value je = parseWhole(jPub.publicExponent.string);
    assert (exists jd);
    assert (exists jn);
    assert (exists je);
    value cKey = RsaExponentPrivateKeyImpl(jd, jn);
    rsaSig.init(cKey);
    value cs = rsaSig.sign(message);
    hexdump(cs);
    assert (cs.sequence() == ss.sequence());
    
    value cPub = RsaPublicKeyImpl(je, jn);
    value verifier = RsaSsaPkcs15Verify(cPub, Sha1());
    assert (verifier.verify(ss, message));
    
}