"""
   A generic ASN.1 value with the information that can minimally be known without knowledge of its type's ASN.1 definition.
"""
shared class GenericAsn1Value(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer)
{
    "The encoded form of the value according to the BER (ASN.1 basic encoding rules).
     The identity octets start at offset 0,
     the length octets start at offset [[lengthOctetsOffset]],
     and the content octets start at offset [[contentOctetsOffset]]."
    shared Byte[] encoded;
    
    "Decoded form of the BER identity octetsof this value."
    shared IdentityInfo identityInfo;
    
    "The start of the length octets in [[encoded]]."
    shared Integer lengthOctetsOffset;
    
    "The start of the content octets in [[encoded]]."
    shared Integer contentOctetsOffset;
    
    "Indicates if the BER encoding of this value violates the DER (ASN.1 distinguished encoding rules), that is,
     if it is **not** in canonical form."
    /* FIXME does that really make sense here? Maybe we should say that without knowing the
       ASN.1 type definition, we cannot say if it violates the DER. */
    shared Boolean violatesDer;
    
    shared Byte[] identityOctets => encoded[...lengthOctetsOffset];
    shared Byte[] lengthOctets => encoded[lengthOctetsOffset .. contentOctetsOffset - 1];
    shared Byte[] contentOctets => encoded[contentOctetsOffset...];
    
    shared default String asn1String => "``identityInfo.tag.asn1String`` ``asn1ValueString``";
    shared default String asn1ValueString => "generic contents ``hexdump(contentOctets)``";
    
    shared actual default String string => "``identityInfo.tag.asn1String`` ``hexdump(contentOctets)``";
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
        extends GenericAsn1Value
        given Value satisfies Anything
{
    Value? storedValue;
    
    shared new direct(Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, Value? val = null)
            extends GenericAsn1Value(encoded, identityInfo, lengthOctetsOffset, contentOctetsOffset, violatesDer)
    {
        this.storedValue = val;
    }
    /*
    shared new decoding(Byte[] encoded, Boolean violatesDer)
    {
        this.encoded = encoded;
        this.violatesDer = violatesDer;
        
        this.storedValue = null;
    }
     */

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
