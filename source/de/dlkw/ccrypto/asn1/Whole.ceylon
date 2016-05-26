import ceylon.whole {
    Whole,
    zero,
    wholeNumber
}

"""
   An ASN.1 INTEGER that can represent arbitrary large values
   using [[ceylon.whole::Whole]].
"""
shared class Asn1Whole extends Asn1Value<Whole>
{
    shared new (Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, Whole valu)
            extends Asn1Value<Whole>.direct(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, valu)
    {}
    
    shared actual String asn1ValueString => "INTEGER ``val``";
    shared actual Tag defaultTag => UniversalTag.integer;
    
    shared actual Boolean equals(Object other)
    {
        if (!is Asn1Integer other) {
            return false;
        }
        return val == other.val;
    }
    
    shared actual Integer hash => val.hash;
}

shared Asn1Whole asn1Whole(Whole valu, Tag tag = UniversalTag.integer)
{
    value identityInfo = IdentityInfo(tag, false);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;
    
    if (valu == 0) {
        return Asn1Whole(identityOctets.append([ #01.byte, #00.byte ]), identityInfo, lengthOctetsOffset, lengthOctetsOffset + 1, false, valu);
    }

    value positive = valu > zero;
    
    variable value val = valu; // :-)
    value minusOne = wholeNumber(-1);
    
    variable Byte[] encoded = [];
    while (val != zero && val != minusOne) {
        encoded = encoded.withLeading(val.integer.byte);
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
    return Asn1Whole(identityOctets.chain(encodedLength).chain(encoded).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size, false, valu);
}

shared class Asn1WholeDecoder(Tag tag = UniversalTag.integer)
        extends Decoder<Asn1Whole>(tag)
{
    shared actual [Asn1Whole, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        if (length == 0) {
            return DecodingError(offset - 1, "INTEGER with length 0 not allowed");
        }

        assert (exists b0 = input[offset]);
        variable Whole val = wholeNumber(b0.signed);
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
                val = val.leftLogicalShift(8).or(wholeNumber(b.unsigned));
            }
        }
        
        Integer nextPos = offset + length;
        value int = Asn1Whole(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset, offset, violatesDer, val);
        return [int, nextPos];
    }
}