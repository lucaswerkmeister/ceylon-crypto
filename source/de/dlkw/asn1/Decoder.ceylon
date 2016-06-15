shared class DecodingError(shared Integer offset, shared String? message = null)
{}


"length, pos of first octet after length octets, DER was violated"
shared [Integer, Integer, Boolean] | DecodingError decodeLengthOctets(Byte[] input, Integer offset)
{
    assert (exists length0 = input[offset]);
    if (length0.get(7)) {
        variable Boolean violatesDer = false;
        
        Integer length1 = length0.and($0111_1111.byte).unsigned;
        if (length1 == 0) {
            violatesDer = true;
            return DecodingError(offset, "decoding method \"``EncodingMethod.constructedIndefiniteLength``\" not supported");
        }
        else {
            variable Integer length = 0;
            for (i in offset + 1 .. offset + length1) {
                assert (exists b = input[i]);
                if (length == 0 && b == 0.byte) {
                    violatesDer = true;
                }
                value lengthN = b.unsigned;
                if (length.and(#ff000000) != 0) {
                    return DecodingError(i, "unsupported length > 32bit");
                }
                length = length.leftLogicalShift(8) + lengthN;
            }
            violatesDer ||= length < 128;
            return [length, offset + length1 + 1, violatesDer];
        }
    }
    else {
        return [length0.unsigned, offset + 1, false];
    }
}

"""
   A decoder for an ASN.1 type.
"""
shared abstract class Decoder<out Asn1Type>("The (IMPLICIT) tag that must be present in the encoding, or null if any tag should be accepted." shared Tag? tag)
        given Asn1Type satisfies GenericAsn1Value
{
    shared Boolean tagMatch(Tag otherTag)
    {
        if (exists tag) {
            return otherTag == tag;
        }
        return true;
    }
    
    "Decodes an ASN.1 value, returning the value and the offset of the next ASN.1 value in [[input]]."
    shared [Asn1Type, Integer] | DecodingError decode("The input to decode. Must be encoded according to the BER." Byte[] input,
        "The offset in [[input]] of the start of the ASN.1 value to decode---the first (or only) identity octet." Integer offset = 0)
    {
        variable Boolean violatesDer = false;
        
        value res0 = decodeIdentityOctets(input, offset);
        if (is DecodingError res0) {
            return res0;
        }
        value [identityOctets, lengthAndContentStart] = res0;
        
        if (!tagMatch(identityOctets.tag)) {
            return DecodingError(offset, "expected tag ``tag else "(cannot happen)"`` but got ``identityOctets.tag``.");
        }
        
        return decodeGivenTag(input, lengthAndContentStart, identityOctets, offset, violatesDer);
    }

    shared [Asn1Type, Integer] | DecodingError decodeGivenTag(input, offset, identityInfo, identityOctetsOffset, violatesDer)
    {
        "The input to decode. Must be encoded according to the BER (without identity octets)."
        Byte[] input;

        "The offset in [[input]] of the start of the length octets of the ASN.1 value to decode."
        Integer offset;
        
        "The already decoded identity octets of the ASN.1 value to decode."
        IdentityInfo identityInfo;

        "The offset in [[input]] of the start of the ASN.1 value to decode---the first (or only) identity octet."
        Integer identityOctetsOffset;

        "Indicates if the decoding of the identity octets of the ASN.1 value to decode violated the DER."
        variable Boolean violatesDer;
        
        value r = decodeLengthOctets(input, offset);
        if (is DecodingError r) {
            return r;
        }
        value [length, contentStart, violate0] = r;
        violatesDer ||= violate0;
        
        return decodeGivenTagAndLength(input, contentStart, identityInfo, length, identityOctetsOffset, offset, violatesDer);
    }
    
    "Decodes the contents octets part of the encoded value. Implementations
     must ensure that they use all contents bits and return a DecodingError if not.
     A DecodingError must also be returned if the input is shorter than indicated by [[length]]."
    shared formal [Asn1Type, Integer] | DecodingError decodeGivenTagAndLength(
        "The input to decode. Must be encoded according to the BER."
        Byte[] input,
        
        "The offset in [[input]] of the first (or only) contents octet.
         If there are no contents octets (like in NULL), this is the offset of the first byte
         after the ASN.1 value."
        Integer offset,
        
        "The already decoded identity octets of the ASN.1 value to decode."
        IdentityInfo identityInfo,

        "The already decoded length octets of the ASN.1 value to decode."
        Integer length,
        
        "The offset in [[input]] of the start of this ASN.1 value. Must lie before [[offset]]."
        Integer identityOctetsOffset,

        "The offset in [[input]] of the first (or only) length octet. Must lie before [[offset]] and after [[identityOctetsOffset]]."
        Integer lengthOctetsOffset,
        
        "Indicates if the decoding of the identity and length octets of the ASN.1 value to decode violated the DER."
        Boolean violatesDer
    );
}

shared abstract class StdDecoder<Asn1Type>(Tag tag)
        extends Decoder<Asn1Type>(tag)
        given Asn1Type satisfies Asn1Value<Anything>
{
    shared actual [Asn1Type, Integer] | DecodingError decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer)
    {
        Byte[] input;
        Integer offset;
        IdentityInfo identityInfo;
        Integer length;
        Integer identityOctetsOffset;
        Integer lengthOctetsOffset;
        Boolean violatesDer;

        Integer nextPos = offset + length;
        
        value encoded = input[offset : length];
        
        value decoded = decodeContents(encoded, identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset);
        if (is DecodingError decoded) {
            // TODO consider variable position field in DecodingError instead
            return DecodingError(offset + decoded.offset, decoded.message);
        }

        return [decoded, nextPos];
    }
    
    shared formal Asn1Type | DecodingError decodeContents(Byte[] contents, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentsOctetsOffset);
}
