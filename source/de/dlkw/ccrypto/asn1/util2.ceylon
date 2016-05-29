shared class TagClass of universal | application | contextSpecific | private
{
    shared Byte highBits;
    
    "workaround for Java backend bug in Ceylon 1.2.2"
    String s;
    
    shared new universal
    {
        highBits => $00.byte.leftLogicalShift(6);
        s => "UNIVERSAL";
    }
    
    shared new application
    {
        highBits => $01.byte.leftLogicalShift(6);
        s => "APPLICATION";
    }
    
    shared new contextSpecific
    {
        highBits => $10.byte.leftLogicalShift(6);
        s => "context-specific";
    }
    
    shared new private
    {
        highBits => $11.byte.leftLogicalShift(6);
        s => "PRIVATE";
    }
    shared actual String string => s;
}

shared class Tag(tagNumber, tagClass = TagClass.contextSpecific)
{
    shared TagClass tagClass;
    shared Integer tagNumber;
    assert (tagNumber >= 0);
    
    shared actual String string => tagClass.string + " " + tagNumber.string;
    shared String asn1String => "[``if (tagClass == TagClass.contextSpecific) then tagNumber else " ".join({ tagClass, tagNumber })``]";
    
    shared actual Boolean equals(Object other)
    {
        if (!is Tag other) {
            return false;
        }
        return tagClass == other.tagClass && tagNumber == other.tagNumber;
    }
    
    shared actual Integer hash
    {
        variable Integer hash = 27;
        hash = (13 * hash) + tagClass.hash;
        hash = (13 * hash) + tagNumber.hash;
        return hash;
    }
}

shared class UniversalTag extends Tag
{
    new tag(Integer tagNumber) extends Tag(tagNumber, TagClass.universal){}

    shared new boolean          extends tag(1){}
    shared new integer          extends tag(2){}
    shared new bitString        extends tag(3){}
    shared new octetString      extends tag(4){}
    shared new null             extends tag(5){}
    shared new objectIdentifier extends tag(6){}
    shared new sequence         extends tag(16){}
    shared new set              extends tag(17){}
    shared new ia5String        extends tag(22){}
    shared new utcTime          extends tag(23){}
    shared new generalizedTime  extends tag(24){}
}

"Information from the identity octets according to the BER"
shared class IdentityInfo(tag, constructed)
{
    shared Tag tag;
    shared Boolean constructed;

    shared Byte[] encoded;
    if (tag.tagNumber <= 30) {
        Byte byte = tag.tagClass.highBits.or(tag.tagNumber.byte);
        if (constructed) {
            encoded = [ byte.set(5) ]; 
        }
        else {
            encoded = [ byte ];
        }
    }
    else {
        variable Byte[] longVal = [ tag.tagNumber.byte.and($0111_1111.byte) ];
        variable Integer t = tag.tagNumber / $1000_0000;
        
        while (t > 0) {
            longVal = longVal.withLeading(t.byte.and($0111_1111.byte).or($1000_0000.byte));
            t = t / $1000_0000;
        }
        Byte b0 = tag.tagClass.highBits.or($1_1111.byte);
        if (constructed) {
            encoded = [ b0.set(5),  *longVal ];
        }
        else {
            encoded = [ b0,  *longVal ];
        }
    }
}

shared class DecodingError(shared Integer offset, shared String? message = null)
{}

shared class EncodingError(shared String? message = null)
{}

"identity octets information, pos of first octet after identity octets, DER was violated"
shared [IdentityInfo, Integer, Boolean] | DecodingError decodeIdentityOctets(Byte[] input, Integer offset = 0)
{
    assert (exists b0 = input[offset]);
    
    Byte tagClassBits = b0.and($1100_0000.byte);
    TagClass tagClass;
    // we have no byte literals...
    switch (tagClassBits.unsigned)
    case ($0000_0000) {
        tagClass = TagClass.universal;
    }
    case ($0100_0000) {
        tagClass = TagClass.application;
    }
    case ($1000_0000) {
        tagClass = TagClass.contextSpecific;
    }
    else {
        tagClass = TagClass.private;
    }
    
    Boolean constructed = b0.get(5);
    
    Integer tagNumber;
    Integer nextPos;
    variable Boolean violatesDer = false;
    Byte tagNumber0 = b0.and($1_1111.byte);
    if (tagNumber0 == $1_1111.byte) {
        variable Integer tmpTagNo = 0;
        variable Integer i = offset + 1;
        variable Boolean goOn = true;
        while (goOn) {
            assert (exists b = input[i]);
            Integer tagN = b.and($0111_1111.byte).unsigned;
            if (tmpTagNo == 0 && tagN == 0) {
                return DecodingError(i, "not as few digits as possible in high-tag-number form");
            }
            if (tmpTagNo.and(#fe000000) != 0) {
                return DecodingError(i, "unsupported tag number > 32bit");
            }
            tmpTagNo = tmpTagNo.leftLogicalShift(7) + tagN;
            goOn = b.get(7);
            i += 1;
        }
        if (tmpTagNo < 128) {
            violatesDer = true;
        }
        tagNumber = tmpTagNo;
        nextPos = i;
    }
    else {
        tagNumber = tagNumber0.unsigned;
        nextPos = offset + 1;
    }
    
    return [IdentityInfo(Tag(tagNumber, tagClass), constructed), nextPos, violatesDer];
}

shared class EncodingMethod of primitiveDefiniteLength | constructedDefiniteLength | constructedIndefiniteLength
{
    shared new primitiveDefiniteLength {}
    shared new constructedDefiniteLength {}
    shared new constructedIndefiniteLength {}
}

"length, pos of first octet after length octets, DER was violated"
shared [Integer, Integer, Boolean] | DecodingError decodeLengthOctets(Byte[] input, Integer offset)
{
    assert (exists length0 = input[offset]);
    if (length0.get(7)) {
        variable Boolean violatesDer = false;
        
        Integer length1 = length0.and($0111_1111.byte).unsigned;
        if (length1 == 0) {
            violatesDer = true;
            return DecodingError(offset, "decoding method ``EncodingMethod.constructedIndefiniteLength`` not supported");
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

shared [Byte+] encodeLength(variable Integer length)
{
    assert (length >= 0);
    if (length < 128) {
        return [ length.byte ];
    }
    
    variable Byte[] encodedLength = [];
    while (length > 0) {
        encodedLength = encodedLength.withLeading(length.byte);
        length /= 256;
    }
    // no worries for length being longer than 127  
    return encodedLength.withLeading(encodedLength.size.byte.or($1000_0000.byte));
}

"""
   A decoder for an ASN.1 type.
"""
shared abstract class Decoder<out Asn1Type>("The (IMPLICIT) tag that must be present in the encoding, or null if any tag should be accepted." shared Tag? tag)
        given Asn1Type satisfies GenericAsn1Value
{
    "Decodes an ASN.1 value, returning the value and the offset of the next ASN.1 value in [[input]]."
    shared [Asn1Type, Integer] | DecodingError decode("The input to decode. Must be encoded according to the BER." Byte[] input,
        "The offset in [[input]] of the start of the ASN.1 value to decode---the first (or only) identity octet." Integer offset = 0)
    {
        variable Boolean violatesDer = false;
        
        value res0 = decodeIdentityOctets(input, offset);
        if (is DecodingError res0) {
            return res0;
        }
        value [identityOctets, lengthAndContentStart, violates0] = res0;
        violatesDer ||= violates0;
        
        if (exists tag) {
            if (identityOctets.tag != tag) {
                return DecodingError(offset, "expected tag ``tag`` but got ``identityOctets.tag``.");
            }
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
    
    shared formal [Asn1Type, Integer] | DecodingError decodeGivenTagAndLength(
        "The input to decode. Must be encoded according to the BER."
        Byte[] input,
        
        "The offset in [[input]] of the first (or only) length octet."
        Integer offset,
        
        "The already decoded identity octets of the ASN.1 value to decode."
        IdentityInfo identityInfo,

        "The already decoded length octets of the ASN.1 value to decode."
        Integer length,
        
        "The offset in [[input]] of the start of this ASN.1 value. Must lie before [[offset]]." Integer identityOctetsOffset,
        Integer lengthOctetsOffset,
        
        "Indicates if the decoding of the identity and length octets of the ASN.1 value to decode violated the DER."
        Boolean violatesDer
    );
}

shared String hexdigits(Byte b) => formatInteger(b.unsigned, 16).padLeading(2, '0');
shared String hexdump({Byte*} bytes) => " ".join(bytes.map((b) => hexdigits(b)));

