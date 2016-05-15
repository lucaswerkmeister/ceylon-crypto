shared interface AnySwitch
{
    shared formal ObjectIdentifier | Asn1Integer relevantDiscriminator(GenericAsn1Value?[] decodedElements);
    
    shared formal Decoder<Asn1Value<Anything>>? selectDecoderDefinedBy(ObjectIdentifier | Asn1Integer discriminator);
    
    shared Decoder<Asn1Value<Anything>> | DecodingError selectDecoder(GenericAsn1Value?[] decodedElements)
    {
        value discriminator = relevantDiscriminator(decodedElements);
        if (exists decoder = selectDecoderDefinedBy(discriminator)) {
            return decoder;
        }
        return DecodingError(-1, "could not determine type of ANY by ``discriminator.asn1String``");
    }
}

shared abstract class AnySwitchRegistry(Map<ObjectIdentifier | Asn1Integer, Decoder<Asn1Value<Anything>>> registeredDecoders)
        satisfies AnySwitch
{
    shared actual Decoder<Asn1Value<Anything>>? selectDecoderDefinedBy(ObjectIdentifier | Asn1Integer discriminator)
    {
        return registeredDecoders.get(discriminator);
    }
}
