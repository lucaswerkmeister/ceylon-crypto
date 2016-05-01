import de.dlkw.ccrypto.api {
    MessageDigester
}
import de.dlkw.ccrypto.api.asn1old.pkcs {
    AlgorithmIdentifier
}
import de.dlkw.ccrypto.api.asn1 {
    Asn1Sequence,
    OctetString,
    octetString,
    asn1Sequence
}

class IntendedEncodedMessageLengthTooShortException() extends Exception(){}
class EmsaPkcs1_v1_5(digester, emLen)
{
    MessageDigester digester;
    Integer hLen => digester.digestLengthOctets;
    
    variable Integer emLen;

    shared EmsaPkcs1_v1_5 init(Integer emLen)
    {
        this.emLen = emLen;
        digester.reset();
        return this;
    }
    
    throws(`class MessageTooLongException`, "the message is too long for the digester")
    shared EmsaPkcs1_v1_5 update({Byte*} messagePart)
    {
        digester.update(messagePart);
        return this;
    }
    
    
    throws(`class MessageTooLongException`, "the message is too long for the digester")
    shared Byte[] finish()
    {
        // 1.
        Byte[] h = digester.digest();
        
        // 2.
        Byte[] t = digestInfoEncodedDER(digester.algorithmIdentifier, h);
        Integer tLen = t.size;
        
        // 3.
        if (emLen < tLen + 11) {
            throw IntendedEncodedMessageLengthTooShortException();
        }
        
        // 4.
        Array<Byte> ps = Array.ofSize(emLen - tLen - 3, #ff.byte);
        
        // 5.
        Byte[] em = { #00.byte, #01.byte }.chain(ps).chain({ #00.byte }).chain(t).sequence();
        
        return em;
    }
}

Byte[] digestInfoEncodedDER(algorithmIdentifier, digest)
{
    AlgorithmIdentifier algorithmIdentifier;
    Byte[] digest;

    Asn1Sequence<[AlgorithmIdentifier, OctetString]> digestInfo = asn1Sequence<[AlgorithmIdentifier, OctetString]>(algorithmIdentifier, octetString(digest));
    return digestInfo.encoded;
}