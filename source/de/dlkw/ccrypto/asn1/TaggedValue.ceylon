shared class TaggedValue<out Type>(Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, Tag tag, Type wrapped)
        extends Asn1Value<Type>.direct(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, wrapped)
        given Type satisfies GenericAsn1Value
{
    shared actual String asn1ValueString => val.asn1String;
    shared actual String asn1String => "``identityInfo.tag.asn1String`` EXPLICIT ``asn1ValueString``";
    shared actual Tag defaultTag => nothing;
    
}

shared TaggedValue<Type> taggedValue<Type>(Type wrapped, Tag tag)
        given Type satisfies GenericAsn1Value
{
    value identityInfo = IdentityInfo(tag, true);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    value encodedLength = encodeLength(wrapped.encoded.size);
    value encoded = identityOctets.chain(encodedLength).chain(wrapped.encoded).sequence();
    return TaggedValue(encoded, identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, tag, wrapped);
}

shared class TaggedValueDecoder<Type>(Tag tag, Decoder<Type> innerDecoder)
        extends Decoder<TaggedValue<Type>>(tag)
        given Type satisfies GenericAsn1Value
{
    shared actual [TaggedValue<Type>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value res1 = decodeIdentityOctets(input, offset);
        if (is DecodingError res1) {
            return res1;
        }
        value [innerId, innerLengthAndContentStart, violates1] = res1;
        if (!innerId.constructed) {
            return DecodingError(identityOctetsOffset, "explicitly tagged value expected, but value is simple type (not structured)");
        }
        violatesDer ||= violates1;
        
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
