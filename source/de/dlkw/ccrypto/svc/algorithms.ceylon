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

"Creates a new instance of a SHA-1 message digester."
shared MessageDigester sha1() => Sha1();

"Creates a new instance of a SHA-256 message digester."
shared MessageDigester sha256() => Sha256();


"Creates a new instance of an RSA Signer using the PKCS #1 RSASSA-PSS signature scheme with
 SHA-1 as hash function and MGF1 with SHA-1 as mask generating function. The salt length
 is set to the digest length of hash function, that is, 20 bytes.
 
 The Signer will use the given RSA private key for the signature creation.

 For the salt, a cryptographically secure random number generator should be used, but because
 of a missing implementation, it is for now up to the caller to provide the salt."
shared Signer sha1WithRsaAndMgf1Sha1Signer(RsaPrivateKey key, {Byte*} saltGenerator)
        => iSha1WithRsaAndMgf1Sha1Signer(key, saltGenerator, 20);

"Creates a new instance of an RSA SignatureVerifier using the PKCS #1 RSASSA-PSS signature scheme with
 SHA-1 as hash function and MGF1 with SHA-1 as mask generating function.
 
 The SignatureVerifier will use the given RSA public key for the signature verification."
shared SignatureVerifier sha1WithRsaAndMgf1Sha1Verifier(RsaPublicKey key)
        => iSha1WithRsaAndMgf1Sha1Verifier(key, 20);

"Creates a new instance of an RSA Signer using the PKCS #1 RSASSA-PSS signature scheme with
 SHA-256 as hash function and MGF1 with SHA-256 as mask generating function. The salt length
 is set to the digest length of the hash function, that is, 32 bytes.
 
 The Signer will use the given RSA private key for the signature creation.

 For the salt, a cryptographically secure random number generator should be used, but because
 of a missing implementation, it is for now up to the caller to provide the salt."
shared Signer sha256WithRsaAndMgf1Sha256Signer(RsaPrivateKey key, {Byte*} saltGenerator)
        => iSha256WithRsaAndMgf1Sha256Signer(key, saltGenerator, 32);

"Creates a new instance of an RSA SignatureVerifier using the PKCS #1 RSASSA-PSS signature scheme with
 SHA-256 as hash function and MGF1 with SHA-256 as mask generating function.
 
 The SignatureVerifier will use the given RSA public key for the signature verification."
shared SignatureVerifier sha256WithRsaAndMgf1Sha256Verifier(RsaPublicKey key)
        => iSha256WithRsaAndMgf1Sha256Verifier(key, 32);


"Creates a new instance of an RSA Signer using the PKCS #1 RSASSA-PKCS-v1_5 signature scheme with
 SHA-1 as hash function.
 
 The Signer will use the given RSA private key for the signature creation."
shared Signer sha1WithRsaSigner(RsaPrivateKey key)
        => iSha1WithRsaSigner(key);

"Creates a new instance of an RSA SignatureVerifier using the PKCS #1 RSASSA-PKCS-v1_5 signature scheme with
 SHA-1 as hash function.
 
 The SignatureVerifier will use the given RSA public key for the signature verification."
shared SignatureVerifier sha1WithRsaVerifier(RsaPublicKey key)
        => iSha1WithRsaVerifier(key);

"Creates a new instance of an RSA Signer using the PKCS #1 RSASSA-PKCS-v1_5 signature scheme with
 SHA-256 as hash function.
 
 The Signer will use the given RSA private key for the signature creation."
shared Signer sha256WithRsaSigner(RsaPrivateKey key)
        => iSha256WithRsaSigner(key);

"Creates a new instance of an RSA SignatureVerifier using the PKCS #1 RSASSA-PKCS-v1_5 signature scheme with
 SHA-256 as hash function.
 
 The SignatureVerifier will use the given RSA public key for the signature verification."
shared SignatureVerifier sha256WithRsaVerifier(RsaPublicKey key)
        => iSha256WithRsaVerifier(key);
