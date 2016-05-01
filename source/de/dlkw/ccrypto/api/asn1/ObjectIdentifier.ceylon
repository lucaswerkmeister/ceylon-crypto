shared class ObjectIdentifier extends Asn1Value<[Integer*]>
{
    shared new internal(Byte[] input, Boolean violatesDer, [Integer*] val)
            extends super.direct(input, violatesDer, val)
    {}
    shared actual [Integer*] decode() => nothing;
    
    shared actual String asn1String => "OBJECT IDENTIFIER ``".".join(val.map((x) => x.string))``";
    
    shared ObjectIdentifier withTrailing(Integer last, Tag tag = UniversalTag.objectIdentifier)
    {
        return objectIdentifier(val.withTrailing(last), tag);
    }
}

shared ObjectIdentifier objectIdentifier([Integer*] parts, Tag tag = UniversalTag.objectIdentifier)
{
    assert (exists n0 = parts[0]);
    assert (exists n1 = parts[1]);
    
    assert (0 <= n0 <= 2);
    if ( n0 < 2) {
        assert (0 <= n1 < 40);
    }
    else {
        assert (0 <= n1 < 256 - 2 * 40);
    }
    
    variable [Byte, Byte*] content = [ (40 * n0 + n1).byte ];
    for (ni in parts[2...]) {
        assert (ni >= 0);
        variable value d = ni / 128;
        variable Byte[] cc = [ (ni % 128).byte ];
        while (d > 0) {
            value rem = (d % 128).byte.or(#80.byte);
            cc = cc.withLeading(rem);
            d = d / 128;
        }
        content = content.append(cc);
    }
    return ObjectIdentifier.internal(IdentityInfo(tag, false).encoded.append(encodeLength(content.size)).append(content), false, parts);
}

shared object objectIdentifierDecoder
        extends Decoder<ObjectIdentifier>()
{
    [Integer, Integer] | DecodingError decodeOidComponent(Byte[] input, variable Integer contentStart)
    {
        variable Integer result = 0;
        while (exists b = input[contentStart++]) {
            if (b.get(7)) {
                value low = b.and($0111_1111.byte);
                if (low == 0.byte) {
                    return DecodingError("not minimum number of octets");
                }
                result = result * 128 + low.unsigned;
            }
            else {
                result = result * 128 + b.unsigned;
                return [result, contentStart];
            }
        }
        return DecodingError("reached end of content octets while decoding OID component (content shorter that indicated by length octets)");
    }

    shared actual [ObjectIdentifier, Integer, Boolean]|DecodingError decodeGivenTag(Byte[] input, Integer offset, Integer identityOctetsOffset)
    {
        variable Boolean violateDer = false;
        value r = decodeLengthOctets(input, offset);
        if (is DecodingError r) {
            return r;
        }
        value [length, contentStart, violate0] = r;
        violateDer ||= violate0;

        value b0 = input[contentStart]?.unsigned;
        if (!exists b0) {
            return DecodingError("unexpected end of input");
        }

        value res0 = if (b0 < 40) then 0 else if (b0 < 80) then 1 else 2;
        value res1 = b0 - res0 * 40;
        variable [Integer, Integer+] result = [res0, res1];

        variable value nextPos = contentStart + 1;
        while (nextPos < contentStart + length) {
            value r0 = decodeOidComponent(input, nextPos);
            if (is DecodingError r0) {
                return r0;
            }
            value [component, nextStart] = r0;
            nextPos = nextStart;

            result = result.withTrailing(component);
        }
        if (nextPos != contentStart + length) {
            return DecodingError("OID content longer than indicated by length octets (last byte has bit 7 set)");
        }
        value oid = ObjectIdentifier.internal(input[identityOctetsOffset:length + contentStart - identityOctetsOffset], violateDer, result);
        return [oid, nextPos, violateDer];
    }
}
