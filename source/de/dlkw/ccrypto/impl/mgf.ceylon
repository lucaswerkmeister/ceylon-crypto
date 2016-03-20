import de.dlkw.ccrypto.api {
    MessageDigester
}

shared interface MaskGeneratingFunction
{
    shared formal Byte[] mask({Byte*} mgfSeed, Integer maskLength);
}

shared class MGF1(MessageDigester digest)
        satisfies MaskGeneratingFunction
{
    digest.reset();

    Integer hLen => digest.digestLengthOctets;
    
    shared actual Byte[] mask({Byte*} mgfSeed, Integer maskLength)
    {
        // supp. n <= 2^32 * hLen
        
        variable Byte[] t = [];
        for (i in 0 .. (maskLength - 1) / hLen + 1) {
            value c = toBytes(i);
            value x = digest.update(mgfSeed).digest(c);
            t = concatenate(t, x);
        }
        return t.take(maskLength).sequence();
    }
}

/*
Byte[] maskG(BlockProcessor digest, {Byte*} message, Integer maskLength)
{
    Integer hLen => digest.blockSize;
    // supp. n <= 2^32 * hLen
    
    variable Byte[] t = [];
    for (i in 0 .. (maskLength - 1) / hLen) {
        value c = toBytes(i);
        value x = digest.updateFinish(message);
        value z = x.chain(c);
        t = concatenate(t, z);
    }
    return t.take(maskLength).sequence();
}
*/
