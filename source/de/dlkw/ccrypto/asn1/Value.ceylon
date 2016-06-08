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
    
    "Decoded form of the BER identity octetsof this value."
    shared IdentityInfo identityInfo;
    
    "The start of the length octets in [[encoded]]."
    shared Integer lengthOctetsOffset;
    
    "The start of the content octets in [[encoded]]."
    shared Integer contentsOctetsOffset;
    
    "Indicates if the BER encoding of this value violates the DER (ASN.1 distinguished encoding rules), that is,
     if it is **not** in canonical form."
    /* FIXME does that really make sense here? Maybe we should say that without knowing the
       ASN.1 type definition, we cannot say if it violates the DER. */
    shared Boolean violatesDer;
    
    shared Byte[] identityOctets => encoded[...lengthOctetsOffset];
    shared Byte[] lengthOctets => encoded[lengthOctetsOffset .. contentsOctetsOffset - 1];
    shared Byte[] contentsOctets => encoded[contentsOctetsOffset...];
    
    "Convenience access to the tag of this value, stored in the [[identityInfo]]."
    shared Tag tag => identityInfo.tag;
    
    shared default String asn1String => "``identityInfo.tag.asn1String`` ``asn1ValueString``";
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

    shared default Value decode(){
        // this error is thrown in subclasses that need to implement it and don't.
        throw AssertionError("decode() needs to be implemented in subclasses that don't store a decoded value!");
    }
    shared Value val => storedValue else decode();
    
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
