import ceylon.buffer.charset {
    utf8
}
import ceylon.buffer.codec {
    EncodeException,
    DecodeException
}

"ASN.1 UTF8String is treated like ASCII."
shared class UTF8String(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
        extends Asn1Value<String>(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentOctetsOffset;
    Boolean violatesDer;
    String valu;

    shared actual String asn1ValueString => "\"``val``\"";
    shared actual Tag defaultTag => UniversalTag.utf8String;
}

"""
   Creates an ASN.1 UTF8String. Restriction from X.690 (07/2002), 8.21.10 is not
   (yet) enforced.
   ("Announcers and escape sequences shall not be used, and each
   character shall be encoded in the smallest number of octets  
   available for that character.")
"""
shared UTF8String | EncodingError utf8String(String val, Tag tag = UniversalTag.utf8String)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    List<Byte> encodedString;
    try {
        encodedString = utf8.encode(val);
    }
    catch (EncodeException e) {
        return EncodingError("Cannot encode UTF8String: ``e.message``");
    }
    value encodedLength = encodeLength(encodedString.size);
    return UTF8String(identityOctets.chain(encodedLength).chain(encodedString).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, val);
}

"
 Decodes an ASN.1 UTF8String. Returns an error if the contents contains octets that are
 not a valid UTF-8 sequence.
"
shared class UTF8StringDecoder(Tag tag = UniversalTag.utf8String)
        extends StdDecoder<UTF8String>(tag)
{
    shared actual UTF8String | DecodingError decodeContents(Byte[] contents, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentsOctetsOffset)
    {
        String string;
        try {
            string = utf8.decode(contents);
        }
        catch (DecodeException e) {
            return DecodingError(0, "Cannot decode UTF8String: ``e.message``");
        }
        
        return UTF8String(contents, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, string);
    }
}
