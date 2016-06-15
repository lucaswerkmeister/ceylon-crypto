import ceylon.test {
    test,
    parameters
}
import ceylon.whole {
    parseWhole,
    one,
    wholeNumber,
    formatWhole
}

import de.dlkw.asn1 {
    hexdump
}
import de.dlkw.ccrypto.impl {
    RsaSsaPssSign,
    os2ip,
    RsaSsaPssVerify,
    RsaExponentPrivateKeyImpl,
    RsaCrtPrivateKeyImpl,
    RsaPublicKeyImpl,
    Sha1,
    MGF1
}

{[Byte[], Byte[], Byte[]]*} messagesInt => {[
    [
        #85.byte, #9e.byte, #ef.byte, #2f.byte, #d7.byte, #8a.byte, #ca.byte, #00.byte,
        #30.byte, #8b.byte, #dc.byte, #47.byte, #11.byte, #93.byte, #bf.byte, #55.byte, 
        
        #bf.byte, #9d.byte, #78.byte, #db.byte, #8f.byte, #8a.byte, #67.byte, #2b.byte,
        #48.byte, #46.byte, #34.byte, #f3.byte, #c9.byte, #c2.byte, #6e.byte, #64.byte,
        
        #78.byte, #ae.byte, #10.byte, #26.byte, #0f.byte, #e0.byte, #dd.byte, #8c.byte,
        #08.byte, #2e.byte, #53.byte, #a5.byte, #29.byte, #3a.byte, #f2.byte, #17.byte,
        
        #3c.byte, #d5.byte, #0c.byte, #6d.byte, #5d.byte, #35.byte, #4f.byte, #eb.byte,
        #f7.byte, #8b.byte, #26.byte, #02.byte, #1c.byte, #25.byte, #c0.byte, #27.byte,
        
        #12.byte, #e7.byte, #8c.byte, #d4.byte, #69.byte, #4c.byte, #9f.byte, #46.byte,
        #97.byte, #77.byte, #e4.byte, #51.byte, #e7.byte, #f8.byte, #e9.byte, #e0.byte,
        
        #4c.byte, #d3.byte, #73.byte, #9c.byte, #6b.byte, #bf.byte, #ed.byte, #ae.byte,
        #48.byte, #7f.byte, #b5.byte, #56.byte, #44.byte, #e9.byte, #ca.byte, #74.byte,
        
        #ff.byte, #77.byte, #a5.byte, #3c.byte, #b7.byte, #29.byte, #80.byte, #2f.byte,
        #6e.byte, #d4.byte, #a5.byte, #ff.byte, #a8.byte, #ba.byte, #15.byte, #98.byte, 
        
        #90.byte, #fc.byte],
        
    [
        #e3.byte, #b5.byte, #d5.byte, #d0.byte, #02.byte, #c1.byte, #bc.byte, #e5.byte,
        #0c.byte, #2b.byte, #65.byte, #ef.byte, #88.byte, #a1.byte, #88.byte, #d8.byte,
        
        #3b.byte, #ce.byte, #7e.byte, #61.byte],
        
    [
        #8d.byte, #aa.byte, #62.byte, #7d.byte, #3d.byte, #e7.byte, #59.byte, #5d.byte,
        #63.byte, #05.byte, #6c.byte, #7e.byte, #c6.byte, #59.byte, #e5.byte, #44.byte,
        
        #06.byte, #f1.byte, #06.byte, #10.byte, #12.byte, #8b.byte, #aa.byte, #e8.byte,
        #21.byte, #c8.byte, #b2.byte, #a0.byte, #f3.byte, #93.byte, #6d.byte, #54.byte,

        #dc.byte, #3b.byte, #dc.byte, #e4.byte, #66.byte, #89.byte, #f6.byte, #b7.byte,
        #95.byte, #1b.byte, #b1.byte, #8e.byte, #84.byte, #05.byte, #42.byte, #76.byte,

        #97.byte, #18.byte, #d5.byte, #71.byte, #5d.byte, #21.byte, #0d.byte, #85.byte,
        #ef.byte, #bb.byte, #59.byte, #61.byte, #92.byte, #03.byte, #2c.byte, #42.byte,

        #be.byte, #4c.byte, #29.byte, #97.byte, #2c.byte, #85.byte, #62.byte, #75.byte,
        #eb.byte, #6d.byte, #5a.byte, #45.byte, #f0.byte, #5f.byte, #51.byte, #87.byte,

        #6f.byte, #c6.byte, #74.byte, #3d.byte, #ed.byte, #dd.byte, #28.byte, #ca.byte,
        #ec.byte, #9b.byte, #b3.byte, #0e.byte, #a9.byte, #9e.byte, #02.byte, #c3.byte,

        #48.byte, #82.byte, #69.byte, #60.byte, #4f.byte, #e4.byte, #97.byte, #f7.byte,
        #4c.byte, #cd.byte, #7c.byte, #7f.byte, #ca.byte, #16.byte, #71.byte, #89.byte,

        #71.byte, #23.byte, #cb.byte, #d3.byte, #0d.byte, #ef.byte, #5d.byte, #54.byte,
        #a2.byte, #b5.byte, #53.byte, #6a.byte, #d9.byte, #0a.byte, #74.byte, #7e.byte]
]};

class TestVectorsInternal()
{
    test
    parameters(`value messagesInt`)
    shared void example1(Byte[] message, Byte[] salt, Byte[] signature)
    {
        hexdump(message);
        hexdump(salt);
        hexdump(signature);
        // ==================================
        // Example 1: A 1024-bit RSA Key Pair
        // ==================================
                
        // ------------------------------
        // Components of the RSA Key Pair
        // ------------------------------
        
        // RSA modulus n:
        // omitted, equals p*q

        // RSA public exponent e:
        value e = [#01.byte, #00.byte, #01.byte];
        
        // RSA private exponent d: 
        // omitted, calculated below from p and q

        // Prime p:
        value pW = parseWhole("d17f655bf27c8b16d35462c905cc04a26f37e2a67fa9c0ce0dced472394a0df743fe7f929e378efdb368eddff453cf007af6d948e0ade757371f8a711e278f6b", 16);
        assert (exists pW);

        // Prime q:
        value qW = parseWhole("c6d92b6fee7414d1358ce1546fb62987530b90bd15e0f14963a5e2635adb69347ec0c01b2ab1763fd8ac1a592fb22757463a982425bb97a3a437c5bf86d03f2f", 16);
        assert (exists qW);

        value m1W = (pW - one) * (qW - one);
        value eW = wholeNumber(#10001);

        value dW = eW.moduloInverse(m1W);
        print(formatWhole(dW, 16));
        
        // p's CRT exponent dP:
        value dP = [ 
           #9d.byte, #0d.byte, #bf.byte, #83.byte, #e5.byte, #ce.byte, #9e.byte, #4b.byte, #17.byte, #54.byte, #dc.byte, #d5.byte, #cd.byte, #05.byte, #bc.byte, #b7.byte, 
           #b5.byte, #5f.byte, #15.byte, #08.byte, #33.byte, #0e.byte, #a4.byte, #9f.byte, #14.byte, #d4.byte, #e8.byte, #89.byte, #55.byte, #0f.byte, #82.byte, #56.byte, 
           #cb.byte, #5f.byte, #80.byte, #6d.byte, #ff.byte, #34.byte, #b1.byte, #7a.byte, #da.byte, #44.byte, #20.byte, #88.byte, #53.byte, #57.byte, #7d.byte, #08.byte, 
           #e4.byte, #26.byte, #28.byte, #90.byte, #ac.byte, #f7.byte, #52.byte, #46.byte, #1c.byte, #ea.byte, #05.byte, #54.byte, #76.byte, #01.byte, #bc.byte, #4f.byte]; 
           
        // q's CRT exponent dQ:
        value dQ = [ 
           #12.byte, #91.byte, #a5.byte, #24.byte, #c6.byte, #b7.byte, #c0.byte, #59.byte, #e9.byte, #0e.byte, #46.byte, #dc.byte, #83.byte, #b2.byte, #17.byte, #1e.byte, 
           #b3.byte, #fa.byte, #98.byte, #81.byte, #8f.byte, #d1.byte, #79.byte, #b6.byte, #c8.byte, #bf.byte, #6c.byte, #ec.byte, #aa.byte, #47.byte, #63.byte, #03.byte, 
           #ab.byte, #f2.byte, #83.byte, #fe.byte, #05.byte, #76.byte, #9c.byte, #fc.byte, #49.byte, #57.byte, #88.byte, #fe.byte, #5b.byte, #1d.byte, #df.byte, #de.byte, 
           #9e.byte, #88.byte, #4a.byte, #3c.byte, #d5.byte, #e9.byte, #36.byte, #b7.byte, #e9.byte, #55.byte, #eb.byte, #f9.byte, #7e.byte, #b5.byte, #63.byte, #b1.byte]; 
        
        // CRT coefficient qInv:
        value qInv = [ 
           #a6.byte, #3f.byte, #1d.byte, #a3.byte, #8b.byte, #95.byte, #0c.byte, #9a.byte, #d1.byte, #c6.byte, #7c.byte, #e0.byte, #d6.byte, #77.byte, #ec.byte, #29.byte,  
           #14.byte, #cd.byte, #7d.byte, #40.byte, #06.byte, #2d.byte, #f4.byte, #2a.byte, #67.byte, #eb.byte, #19.byte, #8a.byte, #17.byte, #6f.byte, #97.byte, #42.byte,  
           #aa.byte, #c7.byte, #c5.byte, #fe.byte, #a1.byte, #4f.byte, #22.byte, #97.byte, #66.byte, #2b.byte, #84.byte, #81.byte, #2c.byte, #4d.byte, #ef.byte, #c4.byte,  
           #9a.byte, #80.byte, #25.byte, #ab.byte, #43.byte, #82.byte, #28.byte, #6b.byte, #e4.byte, #c0.byte, #37.byte, #88.byte, #dd.byte, #01.byte, #d6.byte, #9f.byte];

        value privKey1 = RsaExponentPrivateKeyImpl(dW, pW * qW);

        RsaSsaPssSign rsaSig1 = RsaSsaPssSign(privKey1, Sha1(), MGF1(Sha1()), salt, 20);
        value sig1 = rsaSig1.update(message).sign();
        
        assert (sig1 == signature);
        
        value privKey2 = RsaCrtPrivateKeyImpl(pW, qW, os2ip(dP), os2ip(dQ), os2ip(qInv));
        RsaSsaPssSign rsaSig2 = RsaSsaPssSign(privKey2, Sha1(), MGF1(Sha1()), salt, 20);
        value sig2 = rsaSig2.update(message).sign();
        
        assert (sig2 == signature);

        value pubKey = RsaPublicKeyImpl(os2ip(e), privKey1.modulus);
        RsaSsaPssVerify rsaVerify = RsaSsaPssVerify(pubKey, Sha1(), MGF1(Sha1()), 20);
        rsaVerify.update(message);
        assert (rsaVerify.verify(sig2));
    }
}