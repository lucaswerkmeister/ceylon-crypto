import de.dlkw.ccrypto.svc {
    sha256,
    sha1
}

"Illustrates the use of SHA-256."
shared void runDigestSha256() {
    value digester = sha256();
    digester.update({#61.byte, #62.byte});
    Byte[] digest = digester.digest({#63.byte});
}

"Illustrates the use of SHA-1."
shared void runDigestSha1() {
    value digester = sha1();
    digester.update({#61.byte, #62.byte});
    digester.update({#63.byte});
    Byte[] digest = digester.digest();
}
