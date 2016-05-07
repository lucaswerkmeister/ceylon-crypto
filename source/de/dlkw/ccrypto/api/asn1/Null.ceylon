shared class Asn1Null extends Asn1Value<Null>
{
    shared new (Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer)
            extends Asn1Value<Null>.direct(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, null)
    {}

    shared actual String asn1ValueString => "NULL";
    shared actual Tag defaultTag => UniversalTag.null;
}

shared Asn1Null asn1Null(Tag tag = UniversalTag.null)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    return Asn1Null(identityOctets.withTrailing(0.byte), identityInfo, lengthOctetsOffset, lengthOctetsOffset + 1, false);
}

shared object nullDecoder
        extends Decoder<Asn1Null>()
{
    shared actual [Asn1Null, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        if (length != 0) {
            return DecodingError(offset - 1, "NULL must have length 0");
        }

        return [Asn1Null(input[identityOctetsOffset .. offset - 1], identityInfo, lengthOctetsOffset, lengthOctetsOffset + 1, false), offset];
    }
}