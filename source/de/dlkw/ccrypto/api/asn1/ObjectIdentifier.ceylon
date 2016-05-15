shared class ObjectIdentifier extends Asn1Value<[Integer*]>
{
    shared new internal(Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, Integer[] valu)
            extends Asn1Value<Integer[]>.direct(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, valu)
    {}

    shared actual String asn1ValueString => "OBJECT IDENTIFIER ``".".join(val.map((x) => x.string))``";
    shared actual Tag defaultTag => UniversalTag.objectIdentifier;
    
    shared ObjectIdentifier withTrailing(Integer last, Tag tag = UniversalTag.objectIdentifier)
    {
        return objectIdentifier(val.withTrailing(last), tag);
    }
    
    shared actual Boolean equals(Object other)
    {
        if (!is ObjectIdentifier other) {
            return false;
        }
        return val == other.val;
    }
    
    shared actual Integer hash => val.hash;
}

shared ObjectIdentifier objectIdentifier([Integer*] parts, Tag tag = UniversalTag.objectIdentifier)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;

    assert (exists n0 = parts[0]);
    assert (exists n1 = parts[1]);
    
    assert (0 <= n0 <= 2);
    if ( n0 < 2) {
        assert (0 <= n1 < 40);
    }
    else {
        assert (0 <= n1 < 256 - 2 * 40);
    }
    
    variable [Byte, Byte*] encoded = [ (40 * n0 + n1).byte ];
    for (ni in parts[2...]) {
        assert (ni >= 0);
        variable value d = ni / 128;
        variable Byte[] cc = [ (ni % 128).byte ];
        while (d > 0) {
            value rem = (d % 128).byte.or(#80.byte);
            cc = cc.withLeading(rem);
            d = d / 128;
        }
        encoded = encoded.append(cc);
    }
    
    value encodedLength = encodeLength(encoded.size);
    return ObjectIdentifier.internal(identityOctets.chain(encodedLength).chain(encoded).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, parts);
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
                    return DecodingError(contentStart - 1, "not minimum number of octets");
                }
                result = result * 128 + low.unsigned;
            }
            else {
                result = result * 128 + b.unsigned;
                return [result, contentStart];
            }
        }
        return DecodingError(contentStart, "reached end of content octets while decoding OID component (content shorter that indicated by length octets)");
    }

    shared actual [ObjectIdentifier, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value b0 = input[offset]?.unsigned;
        if (!exists b0) {
            return DecodingError(offset, "unexpected end of input");
        }

        value res0 = if (b0 < 40) then 0 else if (b0 < 80) then 1 else 2;
        value res1 = b0 - res0 * 40;
        variable [Integer, Integer+] result = [res0, res1];

        variable value nextPos = offset + 1;
        while (nextPos < offset + length) {
            value r0 = decodeOidComponent(input, nextPos);
            if (is DecodingError r0) {
                return r0;
            }
            value [component, nextStart] = r0;
            nextPos = nextStart;

            result = result.withTrailing(component);
        }
        if (nextPos != offset + length) {
            return DecodingError(nextPos, "OID content longer than indicated by length octets (last byte has bit 7 set)");
        }

        value oid = ObjectIdentifier.internal(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, result);
        return [oid, nextPos];
    }
}
