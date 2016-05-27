shared class OctetString extends Asn1Value<Byte[]>
{
    shared new (Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentsOctetsOffset, Boolean violatesDer)
            extends Asn1Value<Byte[]>.direct(encoded, identityInfo, lengthOctetsOffset,  contentsOctetsOffset, violatesDer)
    {}

    shared actual Byte[] decode() => encoded[contentsOctetsOffset...];
    shared actual String asn1ValueString => "OCTET STRING ``hexdump(val)``";
    shared actual Tag defaultTag => UniversalTag.octetString;
}

shared OctetString octetString(variable Byte[] val, Tag tag = UniversalTag.octetString)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    value encodedLength = encodeLength(val.size);
    return OctetString(identityOctets.chain(encodedLength).chain(val).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false);
}

shared class OctetStringDecoder(Tag tag = UniversalTag.octetString)
        extends Decoder<OctetString>(tag)
{
    shared actual [OctetString, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        Integer nextPos = offset + length;
        value os = OctetString(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer);
        return [os, nextPos];
    }
}