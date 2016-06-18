import ceylon.buffer.charset {
    ascii
}
import ceylon.buffer.codec {
    EncodeException,
    DecodeException
}

"
 Represent an ASN.1 IA5String value.
 
 IA5String is treated like ASCII."
shared class IA5String(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
        extends Asn1Value<String>(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentOctetsOffset;
    Boolean violatesDer;
    String valu;

    shared actual String asn1ValueString => "\"``val``\"";
    shared actual Tag defaultTag => UniversalTag.ia5String;
}

"
 Creates an ASN.1 IA5String. Returns an error if [[val]] is not representable as ASCII.
"
shared IA5String | EncodingError ia5String(String val, Tag tag = UniversalTag.ia5String)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    List<Byte> encodedString;
    try {
        encodedString = ascii.encode(val);
    }
    catch (EncodeException e) {
        return EncodingError("Cannot encode IA5String: ``e.message``");
    }
    value encodedLength = encodeLength(encodedString.size);
    return IA5String(identityOctets.chain(encodedLength).chain(encodedString).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, val);
}

"
 Decodes an ASN.1 IA5String. Returns an error if the contents contains octets that are
 not ASCII values, that is, if they larger than 127.
"
shared class IA5StringDecoder(Tag tag = UniversalTag.ia5String)
        extends StdDecoder<IA5String>(tag)
{
    shared actual IA5String | DecodingError decodeContents(Byte[] contents, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentsOctetsOffset)
    {
        String string;
        try {
            string = ascii.decode(contents);
        }
        catch (DecodeException e) {
            return DecodingError(0, "Cannot decode IA5String: ``e.message``");
        }
        
        return IA5String(contents, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, string);
    }
}
