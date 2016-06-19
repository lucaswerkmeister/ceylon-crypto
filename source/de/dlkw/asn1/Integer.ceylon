"Represents an ASN.1 INTEGER value, restricted to values representable in 4 octets.
 
 For a larger range, please use [[Asn1Whole]]."
shared class Asn1Integer(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
        extends Asn1Value<Integer>(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer, valu)
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentOctetsOffset;
    Boolean violatesDer;
    Integer valu;

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

"Creates an ASN.1 INTEGER value, implemented by [[Asn1Integer]]"
shared Asn1Integer asn1Integer(valu, tag = UniversalTag.integer)
{
    "The integer value to represent as ASN.1 value."
    Integer valu;
    
    "The (IMPLICIT) tag that should be used in the encoding.
     If omitted, the standard tag of class UNIVERSAL is used."
    Tag tag;

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

"Decodes INTEGER to an [[Asn1Integer]]. Returns an error if the value is not representable in 4 bytes,
 (or if the encoding is invalid)."
shared class Asn1IntegerDecoder(Tag tag = UniversalTag.integer)
        extends Decoder<Asn1Integer>(tag)
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