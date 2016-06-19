"Represents an ASN.1 NULL value."
shared class Asn1Null(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer)
         extends Asn1Value<Null>(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentOctetsOffset;
    Boolean violatesDer;

    shared actual Null decode() => null;
    shared actual String asn1ValueString => "NULL";
    shared actual Tag defaultTag => UniversalTag.null;
    
    shared actual Boolean equals(Object other)
    {
        return other is Asn1Null;
    }
    
    shared actual Integer hash => 0;
}

"Creates an Asn1Null value."
shared Asn1Null asn1Null(tag = UniversalTag.null)
{
    "The (IMPLICIT) tag that should be used in the encoding.
     If omitted, the standard tag of class UNIVERSAL is used."
    Tag tag;
    
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    return Asn1Null(identityOctets.withTrailing(0.byte), identityInfo, lengthOctetsOffset, lengthOctetsOffset + 1, false);
}

"Decodes NULL."
shared class Asn1NullDecoder(Tag tag = UniversalTag.null)
        extends Decoder<Asn1Null>(tag)
{
    shared actual [Asn1Null, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        if (length != 0) {
            return DecodingError(offset - 1, "NULL must have length 0");
        }

        return [Asn1Null(input[identityOctetsOffset .. offset - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, lengthOctetsOffset - identityOctetsOffset + 1, false), offset];
    }
}