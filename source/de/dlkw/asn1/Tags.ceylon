import ceylon.collection {
    ArrayList
}
"An ASN.1 tag consisting of tag class and number."
shared class Tag(tagNumber, tagClass = TagClass.contextSpecific)
{
    "The tag's class." shared TagClass tagClass;
    "The tag's number. Always nonnegative." shared Integer tagNumber;
    assert (tagNumber >= 0);
    
    shared actual String string => tagClass.string + " " + tagNumber.string;
    "String representation that can be used in an ASN.1 listing. (Still in flux)"
    shared String asn1String => "[``if (tagClass == TagClass.contextSpecific) then tagNumber else " ".join({ tagClass, tagNumber })``]";
    
    "Two tags are equal if both their class and their number match."
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

"The class of an ASN.1 tag."
shared class TagClass of universal | application | contextSpecific | private
{
    "The byte mask of the BER encoded tag class in the first (or only) identity octet."
    shared Byte highBits;
    
    // workaround for Java backend bug in Ceylon 1.2.2, cannot directly use string.
    String s;
    
    "class UNIVERSAL for the standard ASN.1 types"
    shared new universal
    {
        highBits => $00.byte.leftLogicalShift(6);
        s => "UNIVERSAL";
    }

    "class APPLICATION"
    shared new application
    {
        highBits => $01.byte.leftLogicalShift(6);
        s => "APPLICATION";
    }
    
    "class context specific, normally used for tagging in SEQUENCEs, SETs, and CHOICE."
    shared new contextSpecific
    {
        highBits => $10.byte.leftLogicalShift(6);
        s => "context-specific";
    }

    "class PRIVATE"
    shared new private
    {
        highBits => $11.byte.leftLogicalShift(6);
        s => "PRIVATE";
    }
    shared actual String string => s;
}

"Information from the identity octets of an ASN.1 value according to the BER."
shared class IdentityInfo(tag, constructed)
{
    "The tag of the ASN.1 value."
    shared Tag tag;
    
    "Indicates if the ASN.1 value is encoded in *constructed* form."
    shared Boolean constructed;
    
    "The identity octets, encoded according to the DER."
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
        value longVal2 = ArrayList<Byte>();
        longVal2.add(tag.tagNumber.byte.and($0111_1111.byte));
        variable Integer t = tag.tagNumber / $1000_0000;
        
        while (t > 0) {
            longVal2.add(t.byte.or($1000_0000.byte));
            t = t / $1000_0000;
        }
        Byte b0 = tag.tagClass.highBits.or($1_1111.byte);
        if (constructed) {
            encoded = [ b0.set(5),  *longVal2.reversed ];
        }
        else {
            encoded = [ b0,  *longVal2.reversed ];
        }
    }
}

"Decodes the identity octets of a BER encoded ASN.1 value.
 
 Returns identity octets information and pos of first octet after identity octets"
shared [IdentityInfo, Integer] | DecodingError decodeIdentityOctets(input, offset = 0)
{
    "The input containing the identity octets to decode."
    Byte[] input;

    "Position in [[input]] where the identity octets (that is, the ASN.1 value) start."
    Integer offset;
        
    assert (exists b0 = input[offset]);
    
    Byte tagClassBits = b0.and($1100_0000.byte);
    
    TagClass tagClass;
    switch (tagClassBits.unsigned) // we have no byte literals...
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
    Byte tagNumber0 = b0.and($1_1111.byte);
    if (tagNumber0 == $1_1111.byte) {
        // indicates that we have a multi-octet tag number
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
        if (tmpTagNo <= 30) {
            return DecodingError(offset + 1, "not as few digits as possible (should use low-tag-number form)");
        }
        tagNumber = tmpTagNo;
        nextPos = i;
    }
    else {
        tagNumber = tagNumber0.unsigned;
        nextPos = offset + 1;
    }
    
    return [IdentityInfo(Tag(tagNumber, tagClass), constructed), nextPos];
}
