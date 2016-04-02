import ceylon.buffer.charset {
    utf8
}
import ceylon.random {
    DefaultRandom
}
import ceylon.whole {
    parseWhole
}

import de.dlkw.ccrypto.api {
    RsaPrivateKey,
    RsaPublicKey,
    KeyPair
}
import de.dlkw.ccrypto.impl {
    RsaPublicKeyImpl,
    RsaExponentPrivateKeyImpl
}
import de.dlkw.ccrypto.svcmgr {
    sha256WithRsaAndMgf1Sha256Signer,
    sha256WithRsaAndMgf1Sha256Verifier,
    sha256WithRsaSigner,
    sha256WithRsaVerifier
}

"Illustrates the use of RSA signature according to PKCS #1 v2.2, signature scheme RSASSA-PSS,
 using SHA-256 as hash algorithm and MGF1 with SHA-256 as mask generating function, together with a
 salt length of 32 (being the hash length of SHA-256)."
shared void runSigRsaSsaPss() {
    value keyPair = createRsaKeyPair();
    value privateKey = keyPair.privateKey;
    value publicKey = keyPair.publicKey;

    String msg = "The adventures of Greggery Peccary";
    value byteMsg = utf8.encode(msg);

    // we don't have a cryptographical random number generator yet, so use a shabby default ;-) random number generator
    value signer = sha256WithRsaAndMgf1Sha256Signer(privateKey, DefaultRandom().bytes());
    value signature = signer.sign(byteMsg);
    
    value verifier = sha256WithRsaAndMgf1Sha256Verifier(publicKey);
    assert (verifier.verify(signature, byteMsg));
}

"Illustrates the use of RSA signature according to PKCS #1 v2.2, signature scheme RSASSA-PKCS1-v1_5,
 using SHA-256 as hash algorithm."
shared void runSigRsaSsaPkcs15() {
    value keyPair = createRsaKeyPair();
    value privateKey = keyPair.privateKey;
    value publicKey = keyPair.publicKey;
    
    String msg = "The adventures of Greggery Peccary";
    value byteMsg = utf8.encode(msg);
    
    // you can use sha1 instead of sha256 below, if you must.
    value signer = sha256WithRsaSigner(privateKey);
    value signature = signer.sign(byteMsg);
    
    value verifier = sha256WithRsaVerifier(publicKey);
    assert (verifier.verify(signature, byteMsg));
}

KeyPair<RsaPrivateKey, RsaPublicKey> createRsaKeyPair()
{
    // this is the 1024 bit key taken from example 1.1 of the test vectors for PKCS #1.
    assert (exists n = parseWhole("a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137", 16));
    assert (exists e = parseWhole("10001", 16));
    assert (exists d = parseWhole("33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325", 16));

    // the only reason to import module impl for now:
    // don't have a key store reader nor a key pair generator yet.
    value private = RsaExponentPrivateKeyImpl(d, n);
    value public = RsaPublicKeyImpl(e, n);
    return KeyPair<RsaPrivateKey, RsaPublicKey>(private, public);  
}
