"Represents an ASN.1 value with an EXPLICIT tag (used in a SEQUENCE, SET or CHOICE)."
shared class TaggedValue<out Type>(Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, Tag tag, Type wrapped)
        extends Asn1Value<Type>(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, wrapped)
        given Type satisfies GenericAsn1Value
{
    shared actual String asn1ValueString => val.asn1String;
    shared actual String asn1String => "``identityInfo.tag.asn1String`` EXPLICIT ``asn1ValueString``";
    shared actual Tag defaultTag => nothing;
    
}

"Creates a TaggedValue, wrapping an ASN.1 value with an explicit tag."
shared TaggedValue<Type> taggedValue<Type>(wrapped, tag)
        given Type satisfies GenericAsn1Value
{
    "The ASN.1 value that shall be explictly tagged."
    Type wrapped;
    
    "The tag to use as explicit tag for the value."
    Tag tag;
    
    value identityInfo = IdentityInfo(tag, true);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    value encodedLength = encodeLength(wrapped.encoded.size);
    value encoded = identityOctets.chain(encodedLength).chain(wrapped.encoded).sequence();
    return TaggedValue(encoded, identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, tag, wrapped);
}

"Decodes an ASN.1 value with an EXPLICIT tag."
shared class TaggedValueDecoder<Type>(tag, innerDecoder)
        extends Decoder<TaggedValue<Type>>(tag)
        given Type satisfies GenericAsn1Value
{
    "The EXPLICIT tag to look for."
    Tag tag;
    
    "The decoder of the wrapped value."
    Decoder<Type> innerDecoder;

    shared actual [TaggedValue<Type>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        if (!identityInfo.constructed) {
            return DecodingError(identityOctetsOffset, "explicitly tagged value expected, but value is simple type (not structured)");
        }

        value res1 = decodeIdentityOctets(input, offset);
        if (is DecodingError res1) {
            return res1;
        }
        value [innerId, innerLengthAndContentStart] = res1;
        
        value res2 = innerDecoder.decodeGivenTag(input, innerLengthAndContentStart, innerId, offset, violatesDer);
        if (is DecodingError res2) {
            return res2;
        }
        value [innerValue, nextStart] = res2;
        violatesDer ||= innerValue.violatesDer;
        
        if (nextStart != offset + length) {
            return DecodingError(nextStart, "explicitly tagged value ends at different pos than wrapped value");
        }
        
        Integer nextPos = offset + length;
        value int = TaggedValue<Type>(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer, identityInfo.tag, innerValue);
        return [int, nextPos];
    }
    
}
