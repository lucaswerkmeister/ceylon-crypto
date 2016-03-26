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
    sha1WithRsaAndMgf1Sha1Verifier,
    sha1WithRsaAndMgf1Sha1Signer,
    sha256WithRsaAndMgf1Sha256Verifier,
    sha256WithRsaAndMgf1Sha256Signer,
    sha256WithRsaSigner,
    sha1WithRsaSigner,
    sha256WithRsaVerifier,
    sha1WithRsaVerifier
}

shared MessageDigester createSha1() => Sha1();

shared MessageDigester createSha256() => Sha256();

shared Signer<RsaPrivateKey> createSha256WithRsaAndMgf1Sha256Signer(RsaPrivateKey key, {Byte*} saltGenerator)
    => sha256WithRsaAndMgf1Sha256Signer(key, saltGenerator, 32);

shared Signer<RsaPrivateKey> createSha1WithRsaAndMgf1Sha1Signer(RsaPrivateKey key, {Byte*} saltGenerator)
    => sha1WithRsaAndMgf1Sha1Signer(key, saltGenerator, 20);

shared SignatureVerifier<RsaPublicKey> createSha256WithRsaAndMgf1Sha256Verifier(RsaPublicKey key)
    => sha256WithRsaAndMgf1Sha256Verifier(key, 32);

shared SignatureVerifier<RsaPublicKey> createSha1WithRsaAndMgf1Sha1Verifier(RsaPublicKey key)
    => sha1WithRsaAndMgf1Sha1Verifier(key, 20);


shared Signer<RsaPrivateKey> createSha256WithRsaSigner(RsaPrivateKey key)
        => sha256WithRsaSigner(key);

shared Signer<RsaPrivateKey> createSha1WithRsaSigner(RsaPrivateKey key)
        => sha1WithRsaSigner(key);

shared SignatureVerifier<RsaPublicKey> createSha256WithRsaVerifier(RsaPublicKey key)
        => sha256WithRsaVerifier(key);

shared SignatureVerifier<RsaPublicKey> createSha1WithRsaVerifier(RsaPublicKey key)
        => sha1WithRsaVerifier(key);
