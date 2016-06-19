import ceylon.language.meta {
    type
}

// FIXME real ugly. Need to ascertain elements and defaults sequence elements are of same Asn1Value
"""
   Encodes an ASN.1 SEQUENCE.
   
   Returns the encoded octets, the identity octets info, the offset of the length octets in the encoded octets, and the the offset of the contents octets.

   If a mandatory element is not given (null), then an EncodingError is returned.
"""
shared [Byte[], IdentityInfo, Integer, Integer] | EncodingError
        encodeAsn1Sequence(elements, defaults, tag)
{
    "The elements to put into the sequence.
     
     An optional element or an element with a DEFAULT value may be passed as [[null]]; in that case, it won't appear in the encoded output.

     An element with a DEFAULT value which is passed as this default value won't appear in the encoded output either (as per the DER).
    "
    Asn1Value<Anything>?[] elements;
    
    """
       A list of default values or optional/mandatory indicators.
       This list must have the same number of elements as the [[elements]] argument.
       
       Each defaults element can either be an [[Option]] value to indicate a mandatory
       or an OPTIONAL sequence component; or it can be an Asn1Value,
       in which case it must have the same type as the corresponding element in
       the [[elements]] argument. In the latter case, it is used as the DEFAULT
       value for the sequence component.
    """
    <Asn1Value<Anything> | Option>[] defaults;
    
    "The (IMPLICIT) tag that should be used in the encoding.
     If omitted, the standard tag of class UNIVERSAL is used."
    Tag tag;
    
    value identityInfo = IdentityInfo(tag, true);
    value identityOctets = identityInfo.encoded;
    value lengthOctetsOffset = identityOctets.size;

    variable {Byte*} contentOctets = [];
    variable Integer length = 0;

    assert (elements.size == defaults.size);
    for (el in zipPairs(elements, defaults)) {
        value [element, default] = el;
        
        if (exists element) {
            value b1 = element.encoded;
            
            if (!is Option default, b1 == default.encoded) {
                // don't encode DEFAULT value
            }
            else {
                length += b1.size;
                contentOctets = contentOctets.chain(b1);
            }
        }
        else {
            if (default == Option.mandatory) {
                return EncodingError("missing (null) value is mandatory");
            }
            // don't encode DEFAULT value or leave out OPTIONAL value
        }
    }
    
    value encodedLength = encodeLength(contentOctets.size);
    return [identityOctets.chain(encodedLength).chain(contentOctets).sequence(), identityInfo, lengthOctetsOffset, lengthOctetsOffset + encodedLength.size];
}

"""
   Represents an ASN.1 SEQUENCE value.
   
   The [[Types]] parameter defines the types the individual components of the
   ASN.1 SEQUENCE. Such a component may cover [[Null]]. This is used
   if (and only if) the SEQUENCE component is OPTIONAL. A sequence instance
   with an omitted optional component is represented as a [[null]] value.
"""
shared class Asn1Sequence<out Types>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Value<Types>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        given Types satisfies [GenericAsn1Value?+]
{
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    Types elements;
    
    shared actual String asn1ValueString => "SEQUENCE { ``" ".join(val.map((x)=>x?.asn1String else "(absent)"))`` }";
    shared actual Tag defaultTag => UniversalTag.sequence;
}

"Represents an ASN.1 SEQUENCE OF value."
shared class Asn1SequenceOf<Inner>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        extends Asn1Value<Inner[]>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, violatesDer, elements)
        given Inner satisfies Asn1Value<Anything>
        {
    Byte[] encoded;
    IdentityInfo identityInfo;
    Integer lengthOctetsOffset;
    Integer contentsOctetsOffset;
    Boolean violatesDer;
    "The components of this SEQUENCE OF."
    Inner[] elements;
    
    shared actual String asn1ValueString => "SEQUENCE OF { ``" ".join(val.map((x)=>x.asn1String))`` }";
    shared actual Tag defaultTag => UniversalTag.sequence;
}

"""
   Creates an Asn1Sequence.
   
   If an element with a default value is passed in as [[null]], then the default
   value (and not null) will be returned in [[Asn1Sequence.val]]. 
"""
// FIXME needs to check a match between the Types and the Asn1Values of the default values
shared Asn1Sequence<Types> | EncodingError asn1Sequence<Types>(elements, defaults, tag = UniversalTag.sequence)
        given Types satisfies [Asn1Value<Anything>?+]
{
    "The elements to put into the sequence.
    
     An optional element or an element with a DEFAULT value may be passed as [[null]]; in that case, it won't appear in the encoded output.

     An element with a DEFAULT value which is passed as this default value won't appear in the encoded output either (as per the DER)."
    Types elements;
    
    """
       A list of default values or optional/mandatory indicators.
       This list must have the same number of elements as the [[elements]] argument.
       
       Each defaults element can either be an [[Option]] value to indicate a mandatory
       or an OPTIONAL sequence component; or it can be an Asn1Value,
       in which case it must have the same type as the corresponding element in
       the [[elements]] argument.
    """
    [Asn1Value<Anything> | Option +] defaults;
    
    "The (IMPLICIT) tag that should be used in the encoding.
     If omitted, the standard tag of class UNIVERSAL is used."
    Tag tag;

    value res = encodeAsn1Sequence(elements, defaults, tag);
    if (is EncodingError res) {
        return res;
    }
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = res;
    
    return Asn1Sequence<Types>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, elements);
}

"""
   Creates an Asn1SequenceOf.
   
   Using different tags on the elements might not make sense in ASN.1. I don't know now.
   It is the user's responsibility that the elements all have the same tag, then.
   """
shared Asn1SequenceOf<Inner> asn1SequenceOf<Inner>(elements, tag = UniversalTag.sequence)
        given Inner satisfies Asn1Value<Anything>
{
    "The sequence components' values to repesent as ASN.1 value."
    Inner[] elements;
    
    "The (IMPLICIT) tag that should be used in the encoding.
     If omitted, the standard tag of class UNIVERSAL is used."
    Tag tag;
    
    value en = encodeAsn1Sequence(elements, elements.collect((_) => Option.mandatory), tag);
    assert (!is EncodingError en);
    
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = en;
    return Asn1SequenceOf<Inner>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, elements);
}

"Enum class to indicate if a sequence/set value is mandatory or optional."
shared class Option of mandatory | optional
{
    String s;
    shared new mandatory{s = "mandatory";}
    shared new optional{s = "optional";}
    shared actual String string => s;
}

"Describes the definition of a SEQUENCE or SET component. Needed because
 not all information is available in the decoders used."
shared class Descriptor<out Element>(decoder, default = Option.mandatory)
given Element satisfies GenericAsn1Value
{
    "Returns a decoder to use for a SEQUENCE or SET component. For most components,
     this will be a constant function, but for components of type ANY, the decoder
     needs to be selected according to the previously decoded components."
    shared <Decoder<Element>|DecodingError>(GenericAsn1Value?[]) decoder;
    
    "Indicates if the component is mandatory or optional, or the
     DEFAULT value of the component if it has one."
    shared Element|Option default;
    
    shared actual String string => "descriptor with ``decoder``, default ``default``";
}

"Decodes a SEQUENCE without knowing the ASN.1 specification for it."
// FIXME probably buggy. need to check (type parameter of Decoder?)
shared class GenericSequenceDecoder(Tag tag = UniversalTag.sequence)
        extends Decoder<Asn1Sequence<Anything>>(tag)
{
    shared actual [Asn1Sequence<Anything>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer contentStart, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        variable Asn1Value<Anything>[] tmpResult = [];
        
        variable Integer startPos = contentStart;
        while (startPos < contentStart + length) {
            value res0 = decodeIdentityOctets(input, startPos);
            if (is DecodingError res0) {
                return res0;
            }
            value [l0, lengthAndContentStart] = res0;
            
            if (l0.tag.tagClass == TagClass.universal) {
                Decoder<Asn1Value<Anything>> decoder;
                if (l0.tag.tagNumber == UniversalTag.integer.tagNumber) {
                    decoder = Asn1IntegerDecoder();
                }
                else if (l0.tag.tagNumber == UniversalTag.octetString.tagNumber) {
                    decoder = OctetStringDecoder();
                }
                else {
                    return DecodingError(startPos, "unsupported tag ``l0.tag``");
                }
                value decoded = decoder.decodeGivenTag(input, lengthAndContentStart, l0, startPos, violatesDer);
                if (is DecodingError decoded) {
                    return decoded;
                }
                value decodedElement = decoded[0];
                violatesDer ||= decodedElement.violatesDer;
                
                tmpResult = tmpResult.withTrailing(decodedElement);
                startPos = decoded[1];
            }
            else {
                return DecodingError(startPos, "cannot decode sequence with tagging when no descriptors are given");
            }
        }
        if (startPos != contentStart + length) {
            return DecodingError(startPos, "SEQUENCE content is longer than described by SEQUENCE's length octet(s)");
        }
        
        "FIXME: support empty sequences"
        assert (is [Asn1Value<Anything>+] result = tmpResult); // FIXME
        value seq = Asn1Sequence<[Asn1Value<Anything>+]>(input[identityOctetsOffset .. startPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, contentStart- identityOctetsOffset, violatesDer, result);
        return [seq, startPos];
    }
}

"Decodes SEQUENCE."
shared class SequenceDecoder<out Types>(els, Tag tag = UniversalTag.sequence)
        extends Decoder<Asn1Sequence<Types>>(tag)
        given Types satisfies [GenericAsn1Value?+]
{
    "Descriptors for decoding of each of the SEQUENCE's components.
     
     The type argument of each descriptor must match the type in the same
     position of the [[Types]] argument."
    Descriptor<GenericAsn1Value>[] els;
    
    shared default actual [Asn1Sequence<Types>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer contentStart, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value defIter = els.iterator();
        
        variable GenericAsn1Value?[] tmpResult = [];
        
        variable Integer startPos = contentStart;
        while (startPos < contentStart + length) {
            value res0 = decodeIdentityOctets(input, startPos);
            if (is DecodingError res0) {
                return res0;
            }
            value [l0, lengthAndContentStart] = res0;
            
            variable Boolean found = false;
            while (!is Finished el = defIter.next()) {
                value decoder = el.decoder(tmpResult);
                if (is DecodingError decoder) {
                    throw AssertionError(decoder.message else "");
                }

                if (decoder.tagMatch(l0.tag)) {
                    value decoded = decoder.decodeGivenTag(input, lengthAndContentStart, l0, startPos, violatesDer);
                    if (is DecodingError decoded) {
                        return decoded;
                    }
                    value decodedElement = decoded[0];
                    violatesDer ||= decodedElement.violatesDer;
                    
                    tmpResult = tmpResult.withTrailing(decodedElement);
                    
                    if (!is Option default = el.default) {
                        if (decodedElement.encoded == default.encoded) {
                            violatesDer = true;
                        }
                    }

                    startPos = decoded[1];
                    found = true;
                    break;
                }
                else {
                    value default = el.default;
                    if (is Option default) {
                        switch (default)
                        case (Option.mandatory) {
                            return DecodingError(startPos, "unexpected tag ``l0.tag`` in sequence, expected ``decoder.tag else "(cannot happen)"``");
                        }
                        case (Option.optional) {
                            tmpResult = tmpResult.withTrailing(null);
                            found = true;
                        }
                    }
                    else {
                        tmpResult = tmpResult.withTrailing(default);
                    }
                }
            }
            if (!found) {
                return DecodingError(startPos, "spurious content of SEQUENCE after last element");
            }
        }
        if (startPos != contentStart + length) {
            return DecodingError(startPos, "SEQUENCE content is longer than described by SEQUENCE's length octet(s)");
        }
        while (!is Finished el = defIter.next()) {
            value default = el.default;
            if (is Option default) {
                switch (default)
                case (Option.mandatory) {
                    value decoder = el.decoder(tmpResult);
                    if (is DecodingError decoder) {
                        throw AssertionError(decoder.message else "");
                    }
                    assert (exists expectedTag = decoder.tag);
                    return DecodingError(startPos, "missing non-optional element with tag ``expectedTag`` at end of SEQUENCE");
                }
                case (Option.optional) {
                    tmpResult = tmpResult.withTrailing(null);
                }
            }
            else {
                tmpResult = tmpResult.withTrailing(default);
            }
        }
        
        value result = tmpResult;
        if (!is Types result) {
            print(tmpResult);
            print(type(tmpResult));
            print(`Types`);
            throw AssertionError("Type mismatch error while sequence decoding. Check type parameters of Asn1Sequence and type parameters of the employed Decoders. Note: OPTIONAL values correspond to intersection types with ceylon.language::Null.");
        }
        value int = Asn1Sequence(input[identityOctetsOffset .. startPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, contentStart - identityOctetsOffset, violatesDer, result);
        return [int, startPos];
    }
}

"Decodes SEQUENCE OF."
shared class SequenceOfDecoder<Inner>(innerDecoder, tag = UniversalTag.sequence)
        extends Decoder<Asn1SequenceOf<Inner>>(tag)
        given Inner satisfies Asn1Value<Anything>
{
    "The decoder to use for the SEQUENCE OF components."
    Decoder<Inner> innerDecoder;

    "The (IMPLICIT) tag that should be used in the encoding.
     If omitted, the standard tag of class UNIVERSAL is used."
    Tag tag;

    shared default actual [Asn1SequenceOf<Inner>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer contentStart, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        variable Inner[] tmpResult = [];
        
        variable Integer startPos = contentStart;
        // FIXME can this be simplified by using innerDecoder.decode()?
        
        while (startPos < contentStart + length) {
            value res0 = decodeIdentityOctets(input, startPos);
            if (is DecodingError res0) {
                return res0;
            }
            value [l0, lengthAndContentStart] = res0;
            
            assert (exists expectedTag = innerDecoder.tag);
            if (l0.tag == expectedTag) {
                value decoded = innerDecoder.decodeGivenTag(input, lengthAndContentStart, l0, startPos, violatesDer);
                if (is DecodingError decoded) {
                    return decoded;
                }
                value decodedElement = decoded[0];
                violatesDer ||= decodedElement.violatesDer;
                
                tmpResult = tmpResult.withTrailing(decodedElement);
                
                startPos = decoded[1];
            }
            else {
                return DecodingError(startPos, "tags of elements in SEQUENCE OF differ");
            }
        }
        if (startPos != contentStart + length) {
            return DecodingError(startPos, "SEQUENCE OF content is longer than described by SEQUENCE OF's length octet(s)");
        }
        
        value int = Asn1SequenceOf(input[identityOctetsOffset .. startPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, contentStart - identityOctetsOffset, violatesDer, tmpResult);
        return [int, startPos];
    }
}
