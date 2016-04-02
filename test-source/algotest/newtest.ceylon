import de.dlkw.ccrypto.impl {
    Sha256
}

shared void newtest()
{
    value sha256 = Sha256();
    sha256.update({#61.byte, #62.byte});
    sha256.update({#63.byte});
    Byte[] digest = sha256.digest();
}
