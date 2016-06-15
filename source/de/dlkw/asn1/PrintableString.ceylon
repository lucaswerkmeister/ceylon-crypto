import ceylon.buffer.charset {
    ascii
}
import ceylon.buffer.codec {
    EncodeException,
    DecodeException
}
import ceylon.whole {
    Whole
}

shared class PrintableString(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
         extends Asn1Value<String>(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentOctetsOffset;
    Boolean violatesDer;
    String valu;
    
    shared actual String asn1ValueString => "\"``val``\"";
    shared actual Tag defaultTag => UniversalTag.printableString;
}

shared PrintableString | EncodingError printableString(String val, Tag tag = UniversalTag.printableString)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;

    for (c in val) {
        if (!('A' <= c <= 'Z' || 'a' <= c <= 'z' || '0' <= c <= '9'
            || " '()+,-./:=?".any((sc) => c == sc))) {
            return EncodingError("invalid character(s) for PrintableString");
        }
    }

    List<Byte> encodedString;
    try {
        encodedString = ascii.encode(val);
    }
    catch (EncodeException e) {
        throw AssertionError("Cannot encode PrintableString, but should be able: ``e.message``");
    }
    value encodedLength = encodeLength(encodedString.size);
    return PrintableString(identityOctets.chain(encodedLength).chain(encodedString).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, val);
}

shared class PrintableStringDecoder(Tag tag = UniversalTag.printableString)
        extends Decoder<PrintableString>(tag)
{
    shared actual [PrintableString, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        Integer nextPos = offset + length;
        
        value contentsOctets = input[offset : length];
        if (contentsOctets.shorterThan(length)) {
            return DecodingError(offset + contentsOctets.size, "reached end of input");
        }
        
        String string;
        try {
            string = ascii.decode(contentsOctets);
        }
        catch (DecodeException e) {
            return DecodingError(offset, "Cannot decode PrintableString: ``e.message``");
        }
        
        for (c in string) {
            if (!('A' <= c <= 'Z' || 'a' <= c <= 'z' || '0' <= c <= '9'
                || " '()+,-./:=?".any((sc) => c == sc))) {
                return DecodingError(offset, "invalid character(s) for PrintableString");
            }
        }

        value os = PrintableString(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer, string);
        return [os, nextPos];
    }
}

shared void xtrun()
{
    value x = printableString("56");
    if (is EncodingError x) {
        print(x.message);
        return;
    }
    print(x.encoded);
    print(x.asn1String);
    
    value y = PrintableStringDecoder().decode([19.byte, 1.byte, 34.byte]);
    if (is DecodingError y) {
        print(y.message);
        return;
    }
    print(y[0].encoded);
    print(y[0].asn1String);
}