import de.dlkw.ccrypto.api {
    MessageDigester
}

shared MessageDigester createSha256() => Sha256();
shared MessageDigester createSha1() => Sha1();
