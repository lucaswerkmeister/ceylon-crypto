import de.dlkw.ccrypto.api.asn1old {
    hexdump
}
shared class OctetString extends Asn1Value<Byte[]>
{
    Integer startContentOffset;
    shared new (Byte[] encoded, Boolean violatesDer, Integer startContentOffset)
            extends Asn1Value<Byte[]>.direct(encoded, violatesDer)
    {
        this.startContentOffset = startContentOffset;
    }

    shared actual Byte[] decode() => encoded[startContentOffset...];
    shared actual String asn1String => "OCTET STRING ``hexdump(val)``";
}

shared OctetString octetString(variable Byte[] val, Tag tag = UniversalTag.octetString)
{
    value identityOctets = IdentityInfo(tag, false).encoded;
    value lengthOctets = encodeLength(val.size);
    return OctetString(identityOctets.chain(lengthOctets).chain(val).sequence(), false, identityOctets.size + lengthOctets.size);
}

shared object octetStringDecoder
        extends Decoder<OctetString>()
{
    shared actual [OctetString, Integer, Boolean] | DecodingError decodeGivenTag(Byte[] input, Integer offset, Integer identityOctetsOffset)
    {
        variable Boolean violatesDer = false;
        
        value r = decodeLengthOctets(input, offset);
        if (is DecodingError r) {
            return r;
        }
        value [length, contentStart, violate0] = r;
        violatesDer ||= violate0;

        return [OctetString(input[identityOctetsOffset .. contentStart + length - 1], violatesDer, contentStart), contentStart + length, violatesDer];
    }
}