import ceylon.buffer.charset {
    ascii
}
import ceylon.buffer.codec {
    EncodeException,
    DecodeException
}

shared class IA5String extends Asn1Value<String>
{
    shared new (Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentsOctetsOffset, Boolean violatesDer, String valu)
            extends Asn1Value<String>.direct(encoded, identityInfo, lengthOctetsOffset,  contentsOctetsOffset, violatesDer, valu)
    {}
    
    shared actual String asn1ValueString => "\"``val``\"";
    shared actual Tag defaultTag => UniversalTag.ia5String;
}

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

shared class IA5StringDecoder(Tag tag = UniversalTag.ia5String)
        extends Decoder<IA5String>(tag)
{
    shared actual [IA5String, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        Integer nextPos = offset + length;
        
        value contentsOctets = input[offset : length];
        if (contentsOctets.size != length) {
            return DecodingError(offset + contentsOctets.size, "reached end of input");
        }
        
        String string;
        try {
            string = ascii.decode(contentsOctets);
        }
        catch (DecodeException e) {
            return DecodingError(offset, "Cannot decode IA5String: ``e.message``");
        }
        
        value os = IA5String(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer, string);
        return [os, nextPos];
    }
}

shared void trun()
{
    value x = ia5String("56");
    if (is EncodingError x) {
        print(x.message);
        return;
    }
    print(x.encoded);
    print(x.asn1String);
    
    value y = IA5StringDecoder().decode([22.byte, 1.byte, #6f.byte]);
    if (is DecodingError y) {
        print(y.message);
        return;
    }
    print(y[0].encoded);
    print(y[0].asn1String);
}