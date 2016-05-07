shared class Asn1Integer extends Asn1Value<Integer>
{
    shared new (Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, Integer valu)
            extends Asn1Value<Integer>.direct(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, valu)
    {}
    
    shared actual String asn1ValueString => "INTEGER ``val``";
    shared actual Tag defaultTag => UniversalTag.integer;
}

shared Asn1Integer asn1Integer(Integer valu, Tag tag = UniversalTag.integer)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    if (valu == 0) {
        return Asn1Integer(identityOctets.append([ #01.byte, #00.byte ]), identityInfo, lengthOctetsOffset, lengthOctetsOffset + 1, false, valu);
    }

    value positive = valu > 0;
    
    variable value val = valu; // :-)
    
    variable Byte[] encoded = [];
    while (val != 0 && val != -1) {
        encoded = encoded.withLeading(val.byte);
        val = val.rightArithmeticShift(8);
    }
    
    if (positive) {
        assert (nonempty vv = encoded);
        if (vv[0].get(7)) {
            encoded = encoded.withLeading(0.byte);
        }
    }
    else {
        if (nonempty vv = encoded) {
            if (!vv[0].get(7)) {
                encoded = encoded.withLeading(#ff.byte);
            }
        }
        else {
            encoded = [#ff.byte];
        }
    }
    value encodedLength = encodeLength(encoded.size);
    return Asn1Integer(identityOctets.chain(encodedLength).chain(encoded).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, valu);
}

shared object asn1IntegerDecoder
        extends Decoder<Asn1Integer>()
{
    shared actual [Asn1Integer, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        if (length == 0) {
            return DecodingError(offset - 1, "INTEGER with length 0 not allowed");
        }
        
        if (length > 4) {
            // BER/DER specifies minimum number of octets,
            // so this check may be done here
            return DecodingError(offset - 1, "INTEGER with length > 4 octets not supported");
        }

        assert (exists b0 = input[offset]);
        variable Integer val = b0.signed;
        if (val == 0 && length > 1) {
            assert (exists b1 = input[offset + 1]);
            if (!b1.get(7)) {
                return DecodingError(offset + 1, "INTEGER must be encoded with minimum number of octets (BER)");
            }
        }
        else if (val == -1 && length > 1) {
            assert (exists b1 = input[offset + 1]);
            if (b1.get(7)) {
                return DecodingError(offset + 1, "INTEGER must be encoded with minimum number of octets (BER)");
            }
        }
        if (1 <= length - 1) {
            for (i in 1 .. length - 1) {
                assert (exists b = input[offset + i]);
                val = val.leftLogicalShift(8).or(b.unsigned);
            }
        }
        
        Integer nextPos = offset + length;
        value int = Asn1Integer(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, val);
        return [int, nextPos];
    }
}