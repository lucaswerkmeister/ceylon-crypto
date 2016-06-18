"""
   A generic ASN.1 value with the information that can minimally be known without knowledge of its type's ASN.1 definition.
"""
shared class GenericAsn1Value(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer)
{
    "The encoded form of the value according to the BER (ASN.1 basic encoding rules).
     The identity octets start at offset 0,
     the length octets start at offset [[lengthOctetsOffset]],
     and the contents octets start at offset [[contentsOctetsOffset]]."
    shared Byte[] encoded;
    
    "Decoded form of the BER encoded identity octets of this value."
    shared IdentityInfo identityInfo;
    
    // TODO ponder if lengthOctetsOffset should really be stored here
    // or re-calculated from encoding when needed.
    "The start of the length octets in [[encoded]]."
    shared Integer lengthOctetsOffset;
    
    // TODO ponder if contentsOctetsOffset should really be stored here
    // or re-calculated from encoding when needed.
    "The start of the content octets in [[encoded]]."
    shared Integer contentsOctetsOffset;
    
    "Indicates if the BER encoding of this value violates the DER (ASN.1 distinguished encoding rules), that is,
     if it is **not** in canonical form."
    // DER can be violated in the encoding of the length!
    shared Boolean violatesDer;
    
    "A Byte sequence consisting of the BER identity octets of this ASN.1 value"
    shared Byte[] identityOctets => encoded[...lengthOctetsOffset - 1];
    "A Byte sequence consisting of the BER length octets of this ASN.1 value"
    shared Byte[] lengthOctets => encoded[lengthOctetsOffset .. contentsOctetsOffset - 1];
    "A Byte sequence consisting of the BER contents octets of this ASN.1 value"
    shared Byte[] contentsOctets => encoded[contentsOctetsOffset...];
    
    "Convenience access to the tag of this value, stored in the [[identityInfo]]."
    shared Tag tag => identityInfo.tag;
    
    "String representation that can be used in an ASN.1 listing. (Still in flux)"
    // FIXME correct this. Determine what to produce here.
    shared default String asn1String => "``identityInfo.tag.asn1String`` ``asn1ValueString``";
    "still not decided when to output what"
    shared default String asn1ValueString => "generic contents ``hexdump(contentsOctets)``";
    
    shared actual default String string => "``identityInfo.tag.asn1String`` ``hexdump(contentsOctets)``";
}

"Decodes an ASN.1 value without knowing its type definition."
shared class GenericAsn1ValueDecoder("The (IMPLICIT) tag that must be present in the encoding, or null if any tag should be accepted." Tag? tag = null)
        extends Decoder<GenericAsn1Value>(tag)
{
    shared actual [GenericAsn1Value, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, Boolean violatesDer)
    {
        Integer nextPos = offset + length;
        value valu = GenericAsn1Value(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer);
        return [valu, nextPos];
    }
}

"Base class for an ASN.1 value whose type definition is known."
shared abstract class Asn1Value<out Value>
        (encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, storedValue = null)
        extends GenericAsn1Value(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer)
        given Value satisfies Anything
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    Value? storedValue;

    "Subclasses must implement this if the decoded value is not stored in the instance
     and thus must be decoded each time [[val]] is called.
     
     If the decoded value is stored in the instance, then this method need not be
     refined."
    shared default Value decode(){
        // this error is thrown in subclasses that need to implement it and don't.
        throw AssertionError("decode() needs to be implemented in subclasses that don't store a decoded value!");
    }
    shared Value val => storedValue else decode();
    
    "The tag that an instance of this class has when used without tag in
     a specification."
    shared formal Tag defaultTag;
    shared default actual String asn1String
    {
        if (identityInfo.tag == defaultTag) {
            return asn1ValueString;
        }
        else {
            return "``identityInfo.tag.asn1String`` IMPLICIT ``asn1ValueString``";
        }
    }
}
