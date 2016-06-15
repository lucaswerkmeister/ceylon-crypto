import de.dlkw.asn1 {
    ObjectIdentifier,
    Asn1Value,
    objectIdentifier,
    encodeAsn1Sequence,
    EncodingError,
    Option,
    IdentityInfo,
    Tag,
    UniversalTag,
    Descriptor,
    Decoder,
    SequenceDecoder,
    DecodingError,
    ObjectIdentifierDecoder,
    GenericAsn1Value,
    AnySwitchRegistry,
    Asn1Null,
    asn1Null,
    Asn1Sequence
}

"""
   Algorithm identifier structure for cryptographic algorithms.
   
   This reflects the AlgorithmIdentifier ASN.1 structure defined in PKCS #1 v2.2,
   which is about the same as the older ASN.1 form from X.509:
   ```asn1
   AlgorithmIdentifier ::= SEQUENCE {
       algorithm OBJECT IDENTIFIER,
       parameters ANY DEFINED BY algorithm OPTIONAL
   }
   ```
   """
shared class AlgorithmIdentifier<out Parameters = Asn1Value<Anything>>(Byte[] encoded, IdentityInfo identityInfo, Integer lengthOctetsOffset, Integer contentOctetsOffset, Boolean violatesDer, [ObjectIdentifier, Parameters?] valu)
        extends Asn1Sequence<[ObjectIdentifier, Parameters?]>(encoded, identityInfo, lengthOctetsOffset,  contentOctetsOffset, violatesDer, valu)
        given Parameters satisfies Asn1Value<Anything>
{
    shared ObjectIdentifier objectIdentifier => val[0];
    shared Parameters? parameters => val[1];
    
    shared actual Boolean equals(Object other)
    {
        if (!is AlgorithmIdentifier<Parameters> other) {
            return false;
        }
        if (objectIdentifier != other.objectIdentifier) {
            return false;
        }
        value p0 = parameters;
        value p1 = other.parameters;
        if (is Null p0) {
            return p1 is Null;
        }
        if (is Null p1) {
            return false;
        }
        return p0 == p1;
    }
}

shared AlgorithmIdentifier<Parameters> algorithmIdentifier<Parameters>(ObjectIdentifier oid, Parameters? parameters, Tag tag = UniversalTag.sequence)
        given Parameters satisfies Asn1Value<Anything>
{
    value x = encodeAsn1Sequence([oid, parameters], [Option.mandatory, Option.optional], tag);
    assert (!is EncodingError x);
    value [encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset] = x;
    return AlgorithmIdentifier<Parameters>(encoded, identityInfo, lengthOctetsOffset, contentsOctetsOffset, false, [oid, parameters]);
}

shared class AlgorithmIdentifierDecoder<P>(<Decoder<P>|DecodingError>(GenericAsn1Value?[]) parameterSelector, Tag tag = UniversalTag.sequence)
        extends Decoder<AlgorithmIdentifier<P>>(tag)
        given P satisfies Asn1Value<Anything>
{
    value delegate = SequenceDecoder<[ObjectIdentifier, P?]>([Descriptor<ObjectIdentifier>((_)=>ObjectIdentifierDecoder()), Descriptor<P>(parameterSelector, Option.optional)]);
    
    shared actual [AlgorithmIdentifier<P>, Integer] | DecodingError decodeGivenTagAndLength(Byte[] input, Integer offset, IdentityInfo identityInfo, Integer length, Integer identityOctetsOffset, Integer lengthOctetsOffset, variable Boolean violatesDer)
    {
        value x = delegate.decodeGivenTagAndLength(input, offset, identityInfo, length, identityOctetsOffset, lengthOctetsOffset, violatesDer);
        if (is DecodingError x) {
            return x;
        }
        value [seq, nextPos] = x;
        violatesDer ||= seq.violatesDer;
        
        value erg = AlgorithmIdentifier<P>(input[identityOctetsOffset .. nextPos - 1], identityInfo, lengthOctetsOffset - identityOctetsOffset, offset - identityOctetsOffset, violatesDer, seq.val);
        return [erg, nextPos];
    }
}

shared class AlgorithmIdentifierAnySwitch(Map<ObjectIdentifier, Decoder<Asn1Value<Anything>>> registeredDecoders)
        extends AnySwitchRegistry(registeredDecoders)
{
    shared actual Integer indexOfRelevantDiscriminator() => 0;
}

/////////////////////////////////
// Object identifiers, well-known
/////////////////////////////////

// prefixes

ObjectIdentifier id_pkcs1 = objectIdentifier([1, 2, 840, 113549, 1, 1]);
ObjectIdentifier id_nistalgorithm = objectIdentifier([2, 16, 840, 1, 101, 3, 4]);
ObjectIdentifier id_nist_hashalgs = id_nistalgorithm.withTrailing(2);

// digest methods (hashes)

"Object identifier for the SHA-1 message digest"
shared ObjectIdentifier id_sha1 = objectIdentifier([1, 3, 14, 3, 2, 26]);

"Object identifier for the SHA-256 message digest"
shared ObjectIdentifier id_sha256 = id_nist_hashalgs.withTrailing(1);

"Object identifier describing an RSA key"
shared ObjectIdentifier id_rsaEncryption = id_pkcs1.withTrailing(1);

"Object identifier describing RSA signature according to PKCS #1, RSASSA-PKCS1-v1_5, using SHA-1 in EMSA-PKCS1-v1_5"
shared ObjectIdentifier id_sha1WithRsaEncryption = id_pkcs1.withTrailing(5);

"Object identifier describing RSA signature according to PKCS #1, RSASSA-PKCS1-v1_5, using SHA-256 in EMSA-PKCS1-v1_5"
shared ObjectIdentifier id_sha256WithRsaEncryption = id_pkcs1.withTrailing(11);

"Object identifier describing the mask generating function MGF1"
shared ObjectIdentifier id_mgf1 = id_pkcs1.withTrailing(8);

"Object identifier describing RSA signature according to PKCS #1, RSASSA-PSS"
shared ObjectIdentifier id_rsaSsaPss = id_pkcs1.withTrailing(10);

// Algorithm identifiers, well-known

"Algorithm identifier describing the SHA-1 message digest"
shared AlgorithmIdentifier<Asn1Null> sha1AlgId = algorithmIdentifier(id_sha1, null);
"Algorithm identifier describing the SHA-1 message digest. Contains an explicit NULL parameter, to be used
 in [[DigestInfo]] (for stupid reasons). Use [[sha1AlgId]] anywhere else."
shared AlgorithmIdentifier<Asn1Null> sha1AlgIdExplicitParam = algorithmIdentifier(id_sha1, asn1Null());
"Algorithm identifier describing the SHA-256 message digest"
shared AlgorithmIdentifier<Asn1Null> sha256AlgId = algorithmIdentifier(id_sha256, null);
"Algorithm identifier describing the SHA-256 message digest. Contains an explicit NULL parameter, to be used
 in [[DigestInfo]] (for stupid reasons). Use [[sha1AlgId]] anywhere else."
shared AlgorithmIdentifier<Asn1Null> sha256AlgIdExplicitParam = algorithmIdentifier(id_sha256, asn1Null());

shared AlgorithmIdentifier<Asn1Null> rsaEncryptionAlgId = algorithmIdentifier(id_rsaEncryption, asn1Null());

shared AlgorithmIdentifier<Asn1Null> sha1WithRsaAlgId = algorithmIdentifier(id_sha1WithRsaEncryption, asn1Null());
shared AlgorithmIdentifier<Asn1Null> sha256WithRsaAlgId = algorithmIdentifier(id_sha256WithRsaEncryption, asn1Null());


shared AlgorithmIdentifier<RsaSsaParameters<Asn1Null, AlgorithmIdentifier<Asn1Null>>> sha1WithRsaSsaPssAndMgf1Sha1 =
        algorithmIdentifier(id_rsaSsaPss, rsaSsaParams(sha1AlgId, algorithmIdentifier(id_mgf1, sha1AlgId), 20));
shared AlgorithmIdentifier<RsaSsaParameters<Asn1Null, AlgorithmIdentifier<Asn1Null>>> sha256WithRsaSsaPssAndMgf1Sha256 =
        algorithmIdentifier(id_rsaSsaPss, rsaSsaParams(sha256AlgId, algorithmIdentifier(id_mgf1, sha256AlgId), 32));

