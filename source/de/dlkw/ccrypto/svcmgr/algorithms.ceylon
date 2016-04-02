import de.dlkw.ccrypto.api {
    MessageDigester,
    Signer,
    SignatureVerifier,
    RsaPrivateKey,
    RsaPublicKey
}
import de.dlkw.ccrypto.impl {
    Sha1,
    Sha256,
    iSha1WithRsaAndMgf1Sha1Verifier = sha1WithRsaAndMgf1Sha1Verifier,
    iSha1WithRsaAndMgf1Sha1Signer = sha1WithRsaAndMgf1Sha1Signer,
    iSha256WithRsaAndMgf1Sha256Verifier = sha256WithRsaAndMgf1Sha256Verifier,
    iSha256WithRsaAndMgf1Sha256Signer = sha256WithRsaAndMgf1Sha256Signer,
    iSha256WithRsaSigner = sha256WithRsaSigner,
    iSha1WithRsaSigner = sha1WithRsaSigner,
    iSha256WithRsaVerifier = sha256WithRsaVerifier,
    iSha1WithRsaVerifier = sha1WithRsaVerifier
}

shared MessageDigester sha1() => Sha1();

shared MessageDigester sha256() => Sha256();


shared Signer sha1WithRsaAndMgf1Sha1Signer(RsaPrivateKey key, {Byte*} saltGenerator)
        => iSha1WithRsaAndMgf1Sha1Signer(key, saltGenerator, 20);

shared SignatureVerifier sha1WithRsaAndMgf1Sha1Verifier(RsaPublicKey key)
        => iSha1WithRsaAndMgf1Sha1Verifier(key, 20);

shared Signer sha256WithRsaAndMgf1Sha256Signer(RsaPrivateKey key, {Byte*} saltGenerator)
        => iSha256WithRsaAndMgf1Sha256Signer(key, saltGenerator, 32);

shared SignatureVerifier sha256WithRsaAndMgf1Sha256Verifier(RsaPublicKey key)
        => iSha256WithRsaAndMgf1Sha256Verifier(key, 32);


shared Signer sha1WithRsaSigner(RsaPrivateKey key)
        => iSha1WithRsaSigner(key);

shared SignatureVerifier sha1WithRsaVerifier(RsaPublicKey key)
        => iSha1WithRsaVerifier(key);

shared Signer sha256WithRsaSigner(RsaPrivateKey key)
        => iSha256WithRsaSigner(key);

shared SignatureVerifier sha256WithRsaVerifier(RsaPublicKey key)
        => iSha256WithRsaVerifier(key);
