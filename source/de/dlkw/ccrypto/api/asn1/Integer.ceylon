shared class Asn1Integer extends Asn1Value<Integer>
{
    shared new (Byte[] encoded, Boolean violatesDer, Integer val)
            extends Asn1Value<Integer>.direct(encoded, violatesDer, val)
    {}
    
    shared actual Integer decode() => nothing;
    shared actual String asn1String => "INTEGER ``val``";
}

shared Asn1Integer asn1Integer(Integer valu, Tag tag = UniversalTag.integer)
{
    value identityOctets = IdentityInfo(tag, false).encoded;
    if (valu == 0) {
        return Asn1Integer(identityOctets.append([ #01.byte, #00.byte ]), false, valu);
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
    return Asn1Integer(identityOctets.chain(encodeLength(encoded.size)).chain(encoded).sequence(), false, valu);
}

shared object asn1IntegerDecoder
        extends Decoder<Asn1Integer>()
{
    shared actual [Asn1Integer, Integer, Boolean] | DecodingError decodeGivenTag(Byte[] input, Integer offset, Integer identityOctetsOffset)
    {
        variable Boolean violatesDer = false;
        
        value r = decodeLengthOctets(input, offset);
        if (is DecodingError r) {
            return r;
        }
        value [length, contentStart, violate0] = r;
        violatesDer ||= violate0;
        
        if (length == 0) {
            return DecodingError("INTEGER with length 0 not allowed");
        }
        
        if (length > 4) {
            // BER/DER specifies minimum number of octets,
            // so this check may be done here
            return DecodingError("INTEGER with length > 4 octets not supported");
        }

        assert (exists b0 = input[contentStart]);
        variable Integer val = b0.signed;
        if (val == 0 && length > 1) {
            assert (exists b1 = input[contentStart + 1]);
            if (!b1.get(7)) {
                return DecodingError("INTEGER must be encoded with minimum number of octets (BER)");
            }
        }
        else if (val == -1 && length > 1) {
            assert (exists b1 = input[contentStart + 1]);
            if (b1.get(7)) {
                return DecodingError("INTEGER must be encoded with minimum number of octets (BER)");
            }
        }
        if (1 <= length - 1) {
            for (i in 1 .. length - 1) {
                assert (exists b = input[contentStart + i]);
                val = val.leftLogicalShift(8).or(b.unsigned);
            }
        }
        
        return [Asn1Integer(input[identityOctetsOffset .. contentStart + length - 1], violatesDer, val), contentStart + length, violatesDer];
    }
}