import de.dlkw.ccrypto.api.asn1 {
    Asn1Value,
    asn1Null,
    ObjectIdentifier,
    Sequence
}

// ####### Message digests #######

shared ObjectIdentifier id_sha1 = ObjectIdentifier(1, 3, 14, 3, 2, 26);
shared ObjectIdentifier id_sha256 = ObjectIdentifier(2, 16, 840, 1, 101, 3, 4, 2, 1);

// ####### PKCS #1 #######

shared ObjectIdentifier pkcs_1 = ObjectIdentifier(1, 2, 840, 113549, 1, 1);
shared ObjectIdentifier sha1WithRsaEncryption = ObjectIdentifier.withPrefix(pkcs_1, 5);
shared ObjectIdentifier sha256WithRsaEncryption = ObjectIdentifier.withPrefix(pkcs_1, 11);
shared ObjectIdentifier id_rsassa_pss = ObjectIdentifier.withPrefix(pkcs_1, 10);
shared ObjectIdentifier id_mgf1 = ObjectIdentifier.withPrefix(pkcs_1, 8);

shared class AlgorithmIdentifier(oid, parameters)
        satisfies Asn1Value
{
    ObjectIdentifier oid;
    Asn1Value parameters;
    
    shared actual [Byte+] der = Sequence(oid, parameters).der;
}

shared AlgorithmIdentifier sha1_x = AlgorithmIdentifier(id_sha1, asn1Null);
