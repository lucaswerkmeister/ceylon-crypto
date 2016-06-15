import ceylon.file {
    home,
    Nil,
    File,
    Writer,
    Reader
}
import ceylon.test {
    test,
    fail
}
import ceylon.time.iso8601 {
    parseDateTime
}
import ceylon.time.timezone {
    timeZone
}

import de.dlkw.ccrypto.api.asn1.pkcs {
    sha1WithRsaAlgId,
    AlgorithmIdentifierAnySwitch,
    rsaEncryptionAlgId,
    sha256WithRsaAlgId,
    id_rsaEncryption,
    id_sha1WithRsaEncryption,
    id_rsaSsaPss,
    RsaSsaParamsDecoder,
    id_sha256WithRsaEncryption
}
import de.dlkw.ccrypto.api.asn1.x509 {
    subjectPublicKeyInfo,
    tbsCertificate,
    attributeValueAssertion,
    rdnSequence,
    relativeDistinguishedName,
    certificate,
    CertificateDecoder
}
import de.dlkw.ccrypto.asn1 {
    EncodingError,
    objectIdentifier,
    bitStringFromBytes,
    printableString,
    hexdump,
    Asn1NullDecoder,
    DecodingError,
    PrintableStringDecoder
}
import de.dlkw.ccrypto.impl {
    rsaPublicKey,
    os2ip,
    rsaCrtPrivateKeyImpl,
    sha1WithRsaSigner,
    publicKeyFrom,
    signatureVerifierFromAlgorithmId
}
import de.dlkw.ccrypto.api {
    SignatureVerifier,
    PublicKey
}

native shared void run();
native("js") shared void run(){}

test
// jvm only just because there's no file writing (ceylon.file) for JavaScript!
native("jvm") shared void run() {
    value path = home.childPath("privKey.der").resource;
    Writer w;
    if (is Nil path) {
        File file = path.createFile();
        w = file.Overwriter();
    }
    else if (is File path){
        w = path.Overwriter();
    }
    else {
        throw AssertionError("");
    }

    // RSA modulus n:
    value n = [
    #a5.byte, #6e.byte, #4a.byte, #0e.byte, #70.byte, #10.byte, #17.byte, #58.byte, #9a.byte, #51.byte, #87.byte, #dc.byte, #7e.byte, #a8.byte, #41.byte, #d1.byte,  
    #56.byte, #f2.byte, #ec.byte, #0e.byte, #36.byte, #ad.byte, #52.byte, #a4.byte, #4d.byte, #fe.byte, #b1.byte, #e6.byte, #1f.byte, #7a.byte, #d9.byte, #91.byte,  
    #d8.byte, #c5.byte, #10.byte, #56.byte, #ff.byte, #ed.byte, #b1.byte, #62.byte, #b4.byte, #c0.byte, #f2.byte, #83.byte, #a1.byte, #2a.byte, #88.byte, #a3.byte,  
    #94.byte, #df.byte, #f5.byte, #26.byte, #ab.byte, #72.byte, #91.byte, #cb.byte, #b3.byte, #07.byte, #ce.byte, #ab.byte, #fc.byte, #e0.byte, #b1.byte, #df.byte,  
    #d5.byte, #cd.byte, #95.byte, #08.byte, #09.byte, #6d.byte, #5b.byte, #2b.byte, #8b.byte, #6d.byte, #f5.byte, #d6.byte, #71.byte, #ef.byte, #63.byte, #77.byte,  
    #c0.byte, #92.byte, #1c.byte, #b2.byte, #3c.byte, #27.byte, #0a.byte, #70.byte, #e2.byte, #59.byte, #8e.byte, #6f.byte, #f8.byte, #9d.byte, #19.byte, #f1.byte,  
    #05.byte, #ac.byte, #c2.byte, #d3.byte, #f0.byte, #cb.byte, #35.byte, #f2.byte, #92.byte, #80.byte, #e1.byte, #38.byte, #6b.byte, #6f.byte, #64.byte, #c4.byte,  
    #ef.byte, #22.byte, #e1.byte, #e1.byte, #f2.byte, #0d.byte, #0c.byte, #e8.byte, #cf.byte, #fb.byte, #22.byte, #49.byte, #bd.byte, #9a.byte, #21.byte, #37.byte]; 

    // RSA public exponent e:
    value e = [#01.byte, #00.byte, #01.byte];

    // RSA private exponent d: 
    value d = [
    #33.byte, #a5.byte, #04.byte, #2a.byte, #90.byte, #b2.byte, #7d.byte, #4f.byte, #54.byte, #51.byte, #ca.byte, #9b.byte, #bb.byte, #d0.byte, #b4.byte, #47.byte, 
    #71.byte, #a1.byte, #01.byte, #af.byte, #88.byte, #43.byte, #40.byte, #ae.byte, #f9.byte, #88.byte, #5f.byte, #2a.byte, #4b.byte, #be.byte, #92.byte, #e8.byte, 
    #94.byte, #a7.byte, #24.byte, #ac.byte, #3c.byte, #56.byte, #8c.byte, #8f.byte, #97.byte, #85.byte, #3a.byte, #d0.byte, #7c.byte, #02.byte, #66.byte, #c8.byte, 
    #c6.byte, #a3.byte, #ca.byte, #09.byte, #29.byte, #f1.byte, #e8.byte, #f1.byte, #12.byte, #31.byte, #88.byte, #44.byte, #29.byte, #fc.byte, #4d.byte, #9a.byte, 
    #e5.byte, #5f.byte, #ee.byte, #89.byte, #6a.byte, #10.byte, #ce.byte, #70.byte, #7c.byte, #3e.byte, #d7.byte, #e7.byte, #34.byte, #e4.byte, #47.byte, #27.byte, 
    #a3.byte, #95.byte, #74.byte, #50.byte, #1a.byte, #53.byte, #26.byte, #83.byte, #10.byte, #9c.byte, #2a.byte, #ba.byte, #ca.byte, #ba.byte, #28.byte, #3c.byte, 
    #31.byte, #b4.byte, #bd.byte, #2f.byte, #53.byte, #c3.byte, #ee.byte, #37.byte, #e3.byte, #52.byte, #ce.byte, #e3.byte, #4f.byte, #9e.byte, #50.byte, #3b.byte, 
    #d8.byte, #0c.byte, #06.byte, #22.byte, #ad.byte, #79.byte, #c6.byte, #dc.byte, #ee.byte, #88.byte, #35.byte, #47.byte, #c6.byte, #a3.byte, #b3.byte, #25.byte]; 
    
    // Prime p:
    value p = [
    #e7.byte, #e8.byte, #94.byte, #27.byte, #20.byte, #a8.byte, #77.byte, #51.byte, #72.byte, #73.byte, #a3.byte, #56.byte, #05.byte, #3e.byte, #a2.byte, #a1.byte, 
    #bc.byte, #0c.byte, #94.byte, #aa.byte, #72.byte, #d5.byte, #5c.byte, #6e.byte, #86.byte, #29.byte, #6b.byte, #2d.byte, #fc.byte, #96.byte, #79.byte, #48.byte, 
    #c0.byte, #a7.byte, #2c.byte, #bc.byte, #cc.byte, #a7.byte, #ea.byte, #cb.byte, #35.byte, #70.byte, #6e.byte, #09.byte, #a1.byte, #df.byte, #55.byte, #a1.byte, 
    #53.byte, #5b.byte, #d9.byte, #b3.byte, #cc.byte, #34.byte, #16.byte, #0b.byte, #3b.byte, #6d.byte, #cd.byte, #3e.byte, #da.byte, #8e.byte, #64.byte, #43.byte]; 
    
    // Prime q:
    value q = [ 
    #b6.byte, #9d.byte, #ca.byte, #1c.byte, #f7.byte, #d4.byte, #d7.byte, #ec.byte, #81.byte, #e7.byte, #5b.byte, #90.byte, #fc.byte, #ca.byte, #87.byte, #4a.byte,  
    #bc.byte, #de.byte, #12.byte, #3f.byte, #d2.byte, #70.byte, #01.byte, #80.byte, #aa.byte, #90.byte, #47.byte, #9b.byte, #6e.byte, #48.byte, #de.byte, #8d.byte,  
    #67.byte, #ed.byte, #24.byte, #f9.byte, #f1.byte, #9d.byte, #85.byte, #ba.byte, #27.byte, #58.byte, #74.byte, #f5.byte, #42.byte, #cd.byte, #20.byte, #dc.byte,  
    #72.byte, #3e.byte, #69.byte, #63.byte, #36.byte, #4a.byte, #1f.byte, #94.byte, #25.byte, #45.byte, #2b.byte, #26.byte, #9a.byte, #67.byte, #99.byte, #fd.byte]; 
    
    // p's CRT exponent dP:
    value dP = [ 
    #28.byte, #fa.byte, #13.byte, #93.byte, #86.byte, #55.byte, #be.byte, #1f.byte, #8a.byte, #15.byte, #9c.byte, #ba.byte, #ca.byte, #5a.byte, #72.byte, #ea.byte, 
    #19.byte, #0c.byte, #30.byte, #08.byte, #9e.byte, #19.byte, #cd.byte, #27.byte, #4a.byte, #55.byte, #6f.byte, #36.byte, #c4.byte, #f6.byte, #e1.byte, #9f.byte, 
    #55.byte, #4b.byte, #34.byte, #c0.byte, #77.byte, #79.byte, #04.byte, #27.byte, #bb.byte, #dd.byte, #8d.byte, #d3.byte, #ed.byte, #e2.byte, #44.byte, #83.byte, 
    #28.byte, #f3.byte, #85.byte, #d8.byte, #1b.byte, #30.byte, #e8.byte, #e4.byte, #3b.byte, #2f.byte, #ff.byte, #a0.byte, #27.byte, #86.byte, #19.byte, #79.byte]; 
    
    // q's CRT exponent dQ:
    value dQ = [ 
    #1a.byte, #8b.byte, #38.byte, #f3.byte, #98.byte, #fa.byte, #71.byte, #20.byte, #49.byte, #89.byte, #8d.byte, #7f.byte, #b7.byte, #9e.byte, #e0.byte, #a7.byte,
    #76.byte, #68.byte, #79.byte, #12.byte, #99.byte, #cd.byte, #fa.byte, #09.byte, #ef.byte, #c0.byte, #e5.byte, #07.byte, #ac.byte, #b2.byte, #1e.byte, #d7.byte,
    #43.byte, #01.byte, #ef.byte, #5b.byte, #fd.byte, #48.byte, #be.byte, #45.byte, #5e.byte, #ae.byte, #b6.byte, #e1.byte, #67.byte, #82.byte, #55.byte, #82.byte,
    #75.byte, #80.byte, #a8.byte, #e4.byte, #e8.byte, #e1.byte, #41.byte, #51.byte, #d1.byte, #51.byte, #0a.byte, #82.byte, #a3.byte, #f2.byte, #e7.byte, #29.byte]; 
    
    // CRT coefficient qInv:
    value qInv = [ 
    #27.byte, #15.byte, #6a.byte, #ba.byte, #41.byte, #26.byte, #d2.byte, #4a.byte, #81.byte, #f3.byte, #a5.byte, #28.byte, #cb.byte, #fb.byte, #27.byte, #f5.byte,
    #68.byte, #86.byte, #f8.byte, #40.byte, #a9.byte, #f6.byte, #e8.byte, #6e.byte, #17.byte, #a4.byte, #4b.byte, #94.byte, #fe.byte, #93.byte, #19.byte, #58.byte,
    #4b.byte, #8e.byte, #22.byte, #fd.byte, #de.byte, #1e.byte, #5a.byte, #2e.byte, #3b.byte, #d8.byte, #aa.byte, #5b.byte, #a8.byte, #d8.byte, #58.byte, #41.byte,
    #94.byte, #eb.byte, #21.byte, #90.byte, #ac.byte, #f8.byte, #32.byte, #b8.byte, #47.byte, #f1.byte, #3a.byte, #3d.byte, #24.byte, #a7.byte, #9f.byte, #4d.byte];
    
    value key = rsaPublicKey(os2ip(e), os2ip(n));
    value privKey = rsaCrtPrivateKeyImpl(os2ip(e), os2ip(d), os2ip(p), os2ip(q), os2ip(dP), os2ip(dQ), os2ip(qInv));

    value notBefore = parseDateTime("2016-06-01T01:04:00")?.instant(timeZone.utc);
    assert (exists notBefore);
    value notAfter = parseDateTime("2016-06-01T03:13:24")?.instant(timeZone.utc);
    assert (exists notAfter);
    value sC = printableString("US");
    assert (!is EncodingError sC);
    value sO = printableString("Example Organization");
    assert (!is EncodingError sO);
    value sCN = printableString("Test User 1");
    assert (!is EncodingError sCN);
    value attC = attributeValueAssertion(objectIdentifier([2, 5, 4, 6]), sC);
    value attO = attributeValueAssertion(objectIdentifier([2, 5, 4, 10]), sO);
    value attCN = attributeValueAssertion(objectIdentifier([2, 5, 4, 3]), sCN);
    value rdn1 = relativeDistinguishedName{avas = [attC];};
    value rdn2 = relativeDistinguishedName{avas = [attO];};
    value rdn3 = relativeDistinguishedName{avas = [attCN];};
//    value rdnSeq = rdnSequence{rdns = [rdn1, rdn2, rdn3];};
    value rdnSeq = rdnSequence{rdns = [rdn1];};
    value bitString = bitStringFromBytes(key.encoded);
    if (is EncodingError bitString) {
        print(bitString.message);
        return;
    }
    value tbsCert = tbsCertificate{
        serialNumber = 5;
        signature = sha1WithRsaAlgId;
        version = 2;
        issuer = rdnSeq;
        notBefore = notBefore;
        notAfter = notAfter;
        subject = rdnSeq;
        subjectPublicKeyInfo = subjectPublicKeyInfo(rsaEncryptionAlgId, bitString);
        extensions = null;
    };
    if (is EncodingError tbsCert) {
        print(tbsCert.message);
        return;
    }
    print(tbsCert.asn1String);
    print(tbsCert.encoded);
    
    value signer = sha1WithRsaSigner(privKey);
    value sig = signer.sign(tbsCert.encoded);
    value cert = certificate(tbsCert, sha1WithRsaAlgId, sig);
    if (is EncodingError cert) {
        print(cert.message);
        return;
    }
    print(cert.asn1String);
    print(cert.encoded);
    print(hexdump(cert.encoded));
    
    w.writeBytes(cert.encoded);
    w.close();

    value keyAnySwitch = AlgorithmIdentifierAnySwitch(map({rsaEncryptionAlgId.objectIdentifier->Asn1NullDecoder()}));
    value sigAnySwitch = AlgorithmIdentifierAnySwitch(map({sha1WithRsaAlgId.objectIdentifier->Asn1NullDecoder()}));
    value nameAnySwitch = AlgorithmIdentifierAnySwitch(map({objectIdentifier([2, 5, 4, 6])->PrintableStringDecoder(),
        objectIdentifier([2, 5, 4, 10])->PrintableStringDecoder(),
        objectIdentifier([2, 5, 4, 3])->PrintableStringDecoder()}));
    value decoder = CertificateDecoder(
        sigAnySwitch,
        nameAnySwitch,
        keyAnySwitch
    );
    value c = decoder.decode(cert.encoded);
    if (is DecodingError c) {
        print(c.message);
        return;
    }
    print(c[0].asn1String);
    print(c[0].encoded);
}

test
// jvm only just because there's no file reading (ceylon.file) for JavaScript!
native("jvm") void readExtCert()
{
    value path = home.childPath("testcert-02.der").resource;
    Reader r;
    if (!is File path){
        throw AssertionError("file missing or not a plain file");
    }
    r = path.Reader();
    
    value cont = r.readBytes(path.size);
    print(hexdump(cont));
    
    // collect all supported public key algorithms here
    value keyAnySwitch = AlgorithmIdentifierAnySwitch(map({id_rsaEncryption->Asn1NullDecoder()}));
    
    // collect all supported signature algorithms here
    value sigAnySwitch = AlgorithmIdentifierAnySwitch(map({
        id_sha1WithRsaEncryption->Asn1NullDecoder(),
        id_sha256WithRsaEncryption->Asn1NullDecoder()}));
    
    // collect all supported RDN attribute types here
    value nameAnySwitch = AlgorithmIdentifierAnySwitch(map({objectIdentifier([2, 5, 4, 6])->PrintableStringDecoder(),
        objectIdentifier([2, 5, 4, 10])->PrintableStringDecoder(),
        objectIdentifier([2, 5, 4, 3])->PrintableStringDecoder()}));
    
    value decoder = CertificateDecoder(
        sigAnySwitch,
        nameAnySwitch,
        keyAnySwitch
    );
    value c = decoder.decode(cont);
    if (is DecodingError c) {
        assert (exists m = c.message);
        fail(m + "(" + c.offset.string + ")");
        return;
    }
    
    value certificate = c[0];
    print(certificate.asn1String);
    print(certificate.encoded);
    
    value key = publicKeyFrom(certificate.subjectPublicKeyInfo);
    if (is DecodingError key) {
        print(key.message);
        return;
    }
   
    SignatureVerifier? verifier = signatureVerifierFromAlgorithmId(certificate.signatureAlgorithm, key);
    assert (exists verifier);
    
    assert(verifier.verify(certificate.signatureValue.bytes, certificate.tbsCertificate.encoded));
    
    // now play around accessing the attributes of the certificate!
    print(certificate.issuer.asn1String);
}
