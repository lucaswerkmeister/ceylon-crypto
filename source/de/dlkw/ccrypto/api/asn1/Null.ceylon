// FIXME provide for implicit tags
shared class Asn1Null extends Asn1Value<Null>
{
    shared new (Byte[] encoded, Boolean violatesDer)
            extends Asn1Value<Null>.direct(encoded, violatesDer, null)
    {}

    shared actual Null decode() => nothing;
    shared actual String asn1String => "NULL";
}

shared Asn1Null asn1Null(Tag tag = UniversalTag.null) => Asn1Null(IdentityInfo(tag, false).encoded.withTrailing(#00.byte), false);

shared object nullDecoder
        extends Decoder<Asn1Null>()
{
    shared actual [Asn1Null, Integer, Boolean] | DecodingError decodeGivenTag(Byte[] input, Integer offset, Integer identityOctetsOffset)
    {
        variable Boolean violatesDer = false;
        
        value r = decodeLengthOctets(input, offset);
        if (is DecodingError r) {
            return r;
        }
        value [length, contentStart, violate0] = r;
        violatesDer ||= violate0;
        
        if (length != 0) {
            return DecodingError("NULL must have length 0");
        }

        return [Asn1Null(input[identityOctetsOffset .. contentStart - 1], violatesDer), contentStart, violatesDer];
    }
}