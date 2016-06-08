
"""
   Parameter types are for octet string contents and number of bits.
   The last octet in the octet string contents may contain unused bits.
"""
shared class BitString(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, unusedBits)
        extends Asn1Value<[Byte[], Integer]>(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentOctetsOffset;
    Boolean violatesDer;
    shared Integer unusedBits;

    shared Byte[] bytes => val[0];
    shared Integer numberOfBits => val[1];
    
    String bitdump(Byte[] val, Integer unusedBits)
    {
        Byte? last = val.last;
        if (is Null last) {
            return "";
        }
        
        Byte[] head = val[0:val.size - 1];
        String s = "".join(head.map((b) => formatInteger(b.unsigned, 2).padLeading(8, '0')));
        String s2 = formatInteger(last.rightLogicalShift(unusedBits).unsigned, 2).padLeading(8 - unusedBits, '0');
        return s + s2;
    }

    shared actual [Byte[], Integer] decode()
    {
        value bytes = encoded[contentsOctetsOffset + 1 ...];
        assert (exists unusedBits = encoded[contentsOctetsOffset]);
        value numberOfBits = bytes.size * 8 - unusedBits.unsigned;
        return [bytes, numberOfBits];
    }
    
    // FIXME like '101'B or '3E7'H
    shared actual String asn1ValueString => "BIT STRING \"``bitdump(bytes, unusedBits)``\"";
    shared actual Tag defaultTag => UniversalTag.bitString;
}

shared BitString | EncodingError bitStringFromBytes(Byte[] bytes, Integer numberOfBits = bytes.size * 8, Tag tag = UniversalTag.bitString)
{
    Integer unusedBits = bytes.size * 8 - numberOfBits;
    if (!(0 <= unusedBits < 8)) {
        return EncodingError("Wrong bytes sequence length ``bytes.size`` for ``numberOfBits`` bits");
    }
    
    if (exists lastByte = bytes.last) {
        Byte mask = (1.leftLogicalShift(unusedBits) - 1).byte;
        if (lastByte.and(mask) != 0.byte) {
            // FIXME maybe instead set unused bits to zero
            return EncodingError("unused bits are not zero");
        }
    }
    else {
        // we checked above that number of bits is zero.
    }

    Byte[] val = bytes.withLeading(unusedBits.byte);
    
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    value encodedLength = encodeLength(val.size);
    return BitString(identityOctets.chain(encodedLength).chain(val).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, unusedBits);
}

shared class BitStringDecoder(Tag tag = UniversalTag.bitString)
        extends Decoder<BitString>(tag)
{
    shared actual [BitString, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        Integer nextPos = offset + length;
        
        value contentsOctets = input[offset .. nextPos - 1];
        value firstByte = contentsOctets[0];
        if (is Null firstByte) {
            return DecodingError(lengthOctetsOffset, "bit string must contain number of unused bits (min. length 1)");
        }
        if (length == 1 && firstByte != 0.byte) {
            return DecodingError(offset, "empty BIT STRING must have 0 unused bits");
        }
        value unusedBits = firstByte.unsigned;
        if (!(0 <= unusedBits < 8)) {
            return DecodingError(offset, "number of unused bits negative or greater than 7");
        }
        
        value os = BitString(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer, unusedBits);
        return [os, nextPos];
    }
}

shared void rrun()
{
    value b = bitStringFromBytes([]);
    if (is EncodingError b) {
        print(b.message);
        return;
    }
    print(b.asn1String);
    print(b.encoded);
    
    value c = BitStringDecoder().decode(b.encoded);
    if (is DecodingError c) {
        print(c.message);
        return;
    }
    print(c[0].asn1String);
    print(c[0].encoded);
}