import de.dlkw.ccrypto {
    createSha256
}

shared void newtest()
{
    value sha256 = createSha256();
    sha256.update({#61.byte, #62.byte});
    sha256.update({#63.byte});
    Byte[] digest = sha256.finish();
}
