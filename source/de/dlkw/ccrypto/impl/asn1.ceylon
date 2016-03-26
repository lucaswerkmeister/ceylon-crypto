import de.dlkw.ccrypto.api.asn1 {
    ObjectIdentifier
}
import de.dlkw.ccrypto.api.asn1.pkcs {
    id_sha1,
    sha1_x,
    sha1WithRsaEncryption
}


ObjectIdentifier test = ObjectIdentifier.withDer([6.byte, 2.byte, 119.byte, 127.byte]);
ObjectIdentifier test2 = ObjectIdentifier.withDer(id_sha1.der);

shared void t()
{
//    tt(identified_organization);
//    tt(id_sha256);
    tt(sha1WithRsaEncryption);
    hexdump(sha1_x.der);
    hexdump(digestInfoEncodedDER(sha1_x, Array<Byte>.ofSize(20, 0.byte).sequence()));
}

void tt(ObjectIdentifier x)
{
    hexdump(x.der);
    print(x.integers);
    for (i in x.integers) {print(i);}
    print(x);
}

