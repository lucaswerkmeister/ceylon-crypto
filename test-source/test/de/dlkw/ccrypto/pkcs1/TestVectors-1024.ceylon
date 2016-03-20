import ceylon.test {
    test,
    parameters
}

import de.dlkw.ccrypto.impl {
    RsaSsaPssSign,
    os2ip,
    RsaSsaPssVerify,
    RsaCrtPrivateKeyImpl,
    RsaExponentPrivateKeyImpl,
    RsaPublicKeyImpl,
    Sha1,
    MGF1
}
import ceylon.whole {
    formatWhole
}

Byte[] conv(String s) {
    value pieces = s.normalized.split((c) => c.whitespace);
    print(":: ``pieces``");
    value c = [ for (b in pieces) parseInteger(b, 16)?.byte ];
    assert (c.every((el) => el exists));
    return c.coalesced.sequence();
}

// # --------------------------------
// # RSASSA-PSS Signature Example 1.1
// # --------------------------------
// 
// # Message to be signed:
 String msg_1_1 = "cd c8 7d a2 23 d7 86 df 3b 45 e0 bb bc 72 13 26 
                   d1 ee 2a f8 06 cc 31 54 75 cc 6f 0d 9c 66 e1 b6 
                   23 71 d4 5c e2 39 2e 1a c9 28 44 c3 10 10 2f 15 
                   6a 0d 8d 52 c1 f4 c4 0b a3 aa 65 09 57 86 cb 76 
                   97 57 a6 56 3b a9 58 fe d0 bc c9 84 e8 b5 17 a3 
                   d5 f5 15 b2 3b 8a 41 e7 4a a8 67 69 3f 90 df b0 
                   61 a6 e8 6d fa ae e6 44 72 c0 0e 5f 20 94 57 29 
                   cb eb e7 7f 06 ce 78 e0 8f 40 98 fb a4 1f 9d 61 
                   93 c0 31 7e 8b 60 d4 b6 08 4a cb 42 d2 9e 38 08 
                   a3 bc 37 2d 85 e3 31 17 0f cb f7 cc 72 d0 b7 1c 
                   29 66 48 b3 a4 d1 0f 41 62 95 d0 80 7a a6 25 ca 
                   b2 74 4f d9 ea 8f d2 23 c4 25 37 02 98 28 bd 16 
                   be 02 54 6f 13 0f d2 e3 3b 93 6d 26 76 e0 8a ed 
                   1b 73 31 8b 75 0a 01 67 d0";

// # Salt:
String salt_1_1 = "de e9 59 c7 e0 64 11 36 14 20 ff 80 18 5e d5 7f 
                   3e 67 76 af"; 
 
// # Signature:
String sig_1_1 = "90 74 30 8f b5 98 e9 70 1b 22 94 38 8e 52 f9 71 
                  fa ac 2b 60 a5 14 5a f1 85 df 52 87 b5 ed 28 87 
                  e5 7c e7 fd 44 dc 86 34 e4 07 c8 e0 e4 36 0b c2 
                  26 f3 ec 22 7f 9d 9e 54 63 8e 8d 31 f5 05 12 15 
                  df 6e bb 9c 2f 95 79 aa 77 59 8a 38 f9 14 b5 b9 
                  c1 bd 83 c4 e2 f9 f3 82 a0 d0 aa 35 42 ff ee 65 
                  98 4a 60 1b c6 9e b2 8d eb 27 dc a1 2c 82 c2 d4 
                  c3 f6 6c d5 00 f1 ff 2b 99 4d 8a 4e 30 cb b3 3c"; 

// # --------------------------------
// # RSASSA-PSS Signature Example 1.2
// # --------------------------------
 
// # Message to be signed:
String msg_1_2 = "85 13 84 cd fe 81 9c 22 ed 6c 4c cb 30 da eb 5c 
                  f0 59 bc 8e 11 66 b7 e3 53 0c 4c 23 3e 2b 5f 8f 
                  71 a1 cc a5 82 d4 3e cc 72 b1 bc a1 6d fc 70 13 
                  22 6b 9e"; 
 
// # Salt:
String salt_1_2 = "ef 28 69 fa 40 c3 46 cb 18 3d ab 3d 7b ff c9 8f 
                   d5 6d f4 2d"; 
 
// # Signature:
String sig_1_2 = "3e f7 f4 6e 83 1b f9 2b 32 27 41 42 a5 85 ff ce 
                  fb dc a7 b3 2a e9 0d 10 fb 0f 0c 72 99 84 f0 4e 
                  f2 9a 9d f0 78 07 75 ce 43 73 9b 97 83 83 90 db 
                  0a 55 05 e6 3d e9 27 02 8d 9d 29 b2 19 ca 2c 45 
                  17 83 25 58 a5 5d 69 4a 6d 25 b9 da b6 60 03 c4 
                  cc cd 90 78 02 19 3b e5 17 0d 26 14 7d 37 b9 35 
                  90 24 1b e5 1c 25 05 5f 47 ef 62 75 2c fb e2 14 
                  18 fa fe 98 c2 2c 4d 4d 47 72 4f db 56 69 e8 43"; 

// # --------------------------------
// # RSASSA-PSS Signature Example 1.3
// # --------------------------------
 
// # Message to be signed:
String msg_1_3 = "a4 b1 59 94 17 61 c4 0c 6a 82 f2 b8 0d 1b 94 f5 
                  aa 26 54 fd 17 e1 2d 58 88 64 67 9b 54 cd 04 ef 
                  8b d0 30 12 be 8d c3 7f 4b 83 af 79 63 fa ff 0d 
                  fa 22 54 77 43 7c 48 01 7f f2 be 81 91 cf 39 55 
                  fc 07 35 6e ab 3f 32 2f 7f 62 0e 21 d2 54 e5 db 
                  43 24 27 9f e0 67 e0 91 0e 2e 81 ca 2c ab 31 c7 
                  45 e6 7a 54 05 8e b5 0d 99 3c db 9e d0 b4 d0 29 
                  c0 6d 21 a9 4c a6 61 c3 ce 27 fa e1 d6 cb 20 f4 
                  56 4d 66 ce 47 67 58 3d 0e 5f 06 02 15 b5 90 17 
                  be 85 ea 84 89 39 12 7b d8 c9 c4 d4 7b 51 05 6c 
                  03 1c f3 36 f1 7c 99 80 f3 b8 f5 b9 b6 87 8e 8b 
                  79 7a a4 3b 88 26 84 33 3e 17 89 3f e9 ca a6 aa 
                  29 9f 7e d1 a1 8e e2 c5 48 64 b7 b2 b9 9b 72 61 
                  8f b0 25 74 d1 39 ef 50 f0 19 c9 ee f4 16 97 13 
                  38 e7 d4 70";
 
// # Salt:
String salt_1_3 = "71 0b 9c 47 47 d8 00 d4 de 87 f1 2a fd ce 6d f1 
                   81 07 cc 77";
 
// # Signature:
String sig_1_3 = "66 60 26 fb a7 1b d3 e7 cf 13 15 7c c2 c5 1a 8e 
                  4a a6 84 af 97 78 f9 18 49 f3 43 35 d1 41 c0 01 
                  54 c4 19 76 21 f9 62 4a 67 5b 5a bc 22 ee 7d 5b 
                  aa ff aa e1 c9 ba ca 2c c3 73 b3 f3 3e 78 e6 14 
                  3c 39 5a 91 aa 7f ac a6 64 eb 73 3a fd 14 d8 82 
                  72 59 d9 9a 75 50 fa ca 50 1e f2 b0 4e 33 c2 3a 
                  a5 1f 4b 9e 82 82 ef db 72 8c c0 ab 09 40 5a 91 
                  60 7c 63 69 96 1b c8 27 0d 2d 4f 39 fc e6 12 b1"; 
 
// # --------------------------------
// # RSASSA-PSS Signature Example 1.4
// # --------------------------------
 
// # Message to be signed:
String msg_1_4 = "bc 65 67 47 fa 9e af b3 f0"; 
 
// # Salt:
String salt_1_4 = "05 6f 00 98 5d e1 4d 8e f5 ce a9 e8 2f 8c 27 be 
                   f7 20 33 5e ";
 
// # Signature:
String sig_1_4= "46 09 79 3b 23 e9 d0 93 62 dc 21 bb 47 da 0b 4f 
                 3a 76 22 64 9a 47 d4 64 01 9b 9a ea fe 53 35 9c 
                 17 8c 91 cd 58 ba 6b cb 78 be 03 46 a7 bc 63 7f 
                 4b 87 3d 4b ab 38 ee 66 1f 19 96 34 c5 47 a1 ad 
                 84 42 e0 3d a0 15 b1 36 e5 43 f7 ab 07 c0 c1 3e 
                 42 25 b8 de 8c ce 25 d4 f6 eb 84 00 f8 1f 7e 18 
                 33 b7 ee 6e 33 4d 37 09 64 ca 79 fd b8 72 b4 d7 
                 52 23 b5 ee b0 81 01 59 1f b5 32 d1 55 a6 de 87 ";
 
// # --------------------------------
// # RSASSA-PSS Signature Example 1.5
// # --------------------------------
 
// # Message to be signed:
String msg_1_5 = "b4 55 81 54 7e 54 27 77 0c 76 8e 8b 82 b7 55 64 
                  e0 ea 4e 9c 32 59 4d 6b ff 70 65 44 de 0a 87 76 
                  c7 a8 0b 45 76 55 0e ee 1b 2a ca bc 7e 8b 7d 3e 
                  f7 bb 5b 03 e4 62 c1 10 47 ea dd 00 62 9a e5 75 
                  48 0a c1 47 0f e0 46 f1 3a 2b f5 af 17 92 1d c4 
                  b0 aa 8b 02 be e6 33 49 11 65 1d 7f 85 25 d1 0f 
                  32 b5 1d 33 be 52 0d 3d df 5a 70 99 55 a3 df e7 
                  82 83 b9 e0 ab 54 04 6d 15 0c 17 7f 03 7f dc cc 
                  5b e4 ea 5f 68 b5 e5 a3 8c 9d 7e dc cc c4 97 5f 
                  45 5a 69 09 b4 ";
 
// # Salt:
String salt_1_5 = "80 e7 0f f8 6a 08 de 3e c6 09 72 b3 9b 4f bf dc 
                   ea 67 ae 8e ";
 
// # Signature:
String sig_1_5= "1d 2a ad 22 1c a4 d3 1d df 13 50 92 39 01 93 98 
                 e3 d1 4b 32 dc 34 dc 5a f4 ae ae a3 c0 95 af 73 
                 47 9c f0 a4 5e 56 29 63 5a 53 a0 18 37 76 15 b1 
                 6c b9 b1 3b 3e 09 d6 71 eb 71 e3 87 b8 54 5c 59 
                 60 da 5a 64 77 6e 76 8e 82 b2 c9 35 83 bf 10 4c 
                 3f db 23 51 2b 7b 4e 89 f6 33 dd 00 63 a5 30 db 
                 45 24 b0 1c 3f 38 4c 09 31 0e 31 5a 79 dc d3 d6 
                 84 02 2a 7f 31 c8 65 a6 64 e3 16 97 8b 75 9f ad ";
 
// # --------------------------------
// # RSASSA-PSS Signature Example 1.6
// # --------------------------------
 
// # Message to be signed:
String msg_1_6 = "10 aa e9 a0 ab 0b 59 5d 08 41 20 7b 70 0d 48 d7 
                  5f ae dd e3 b7 75 cd 6b 4c c8 8a e0 6e 46 94 ec 
                  74 ba 18 f8 52 0d 4f 5e a6 9c bb e7 cc 2b eb a4 
                  3e fd c1 02 15 ac 4e b3 2d c3 02 a1 f5 3d c6 c4 
                  35 22 67 e7 93 6c fe bf 7c 8d 67 03 57 84 a3 90 
                  9f a8 59 c7 b7 b5 9b 8e 39 c5 c2 34 9f 18 86 b7 
                  05 a3 02 67 d4 02 f7 48 6a b4 f5 8c ad 5d 69 ad 
                  b1 7a b8 cd 0c e1 ca f5 02 5a f4 ae 24 b1 fb 87 
                  94 c6 07 0c c0 9a 51 e2 f9 91 13 11 e3 87 7d 00 
                  44 c7 1c 57 a9 93 39 50 08 80 6b 72 3a c3 83 73 
                  d3 95 48 18 18 52 8c 1e 70 53 73 92 82 05 35 29 
                  51 0e 93 5c d0 fa 77 b8 fa 53 cc 2d 47 4b d4 fb 
                  3c c5 c6 72 d6 ff dc 90 a0 0f 98 48 71 2c 4b cf 
                  e4 6c 60 57 36 59 b1 1e 64 57 e8 61 f0 f6 04 b6 
                  13 8d 14 4f 8c e4 e2 da 73"; 
 
// # Salt:
String salt_1_6 = "a8 ab 69 dd 80 1f 00 74 c2 a1 fc 60 64 98 36 c6 
                   16 d9 96 81 ";
 
// # Signature:
String sig_1_6= "2a 34 f6 12 5e 1f 6b 0b f9 71 e8 4f bd 41 c6 32 
                 be 8f 2c 2a ce 7d e8 b6 92 6e 31 ff 93 e9 af 98 
                 7f bc 06 e5 1e 9b e1 4f 51 98 f9 1f 3f 95 3b d6 
                 7d a6 0a 9d f5 97 64 c3 dc 0f e0 8e 1c be f0 b7 
                 5f 86 8d 10 ad 3f ba 74 9f ef 59 fb 6d ac 46 a0 
                 d6 e5 04 36 93 31 58 6f 58 e4 62 8f 39 aa 27 89 
                 82 54 3b c0 ee b5 37 dc 61 95 80 19 b3 94 fb 27 
                 3f 21 58 58 a0 a0 1a c4 d6 50 b9 55 c6 7f 4c 58"; 
 
 [[Byte[], Byte[], Byte[]]*] messages1024 = [
    [conv(msg_1_1), conv(salt_1_1), conv(sig_1_1)],
    [conv(msg_1_2), conv(salt_1_2), conv(sig_1_2)],
    [conv(msg_1_3), conv(salt_1_3), conv(sig_1_3)],
    [conv(msg_1_4), conv(salt_1_4), conv(sig_1_4)],
    [conv(msg_1_5), conv(salt_1_5), conv(sig_1_5)],
    [conv(msg_1_6), conv(salt_1_6), conv(sig_1_6)]
];

class TestVectors1024()
{
    test
    parameters(`value messages1024`)
    shared void example1(Byte[] message, Byte[] salt, Byte[] signature)
    {
        assert (exists a = messages1024.first);
        value a0 = a[0];
        value a1 = a[1];
        value a2 = a[2];
        // ==================================
        // Example 1: A 1024-bit RSA Key Pair
        // ==================================
                
        // ------------------------------
        // Components of the RSA Key Pair
        // ------------------------------
        
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
           
        print("key e:``formatWhole(os2ip(e), 16)``");
        print("key d: ``formatWhole(os2ip(d), 16)``");
        print("key n: ``formatWhole(os2ip(n), 16)``");

        value privKey1 = RsaCrtPrivateKeyImpl(os2ip(p), os2ip(q), os2ip(dP), os2ip(dQ), os2ip(qInv));
        RsaSsaPssSign rsaSig1 = RsaSsaPssSign(privKey1, Sha1(), MGF1(Sha1()), salt, 20);
        value sig1 = rsaSig1.update(message).sign();
        
        assert (sig1 == signature);
        
        value privKey2 = RsaExponentPrivateKeyImpl(os2ip(d), os2ip(n));
        RsaSsaPssSign rsaSig2 = RsaSsaPssSign(privKey2, Sha1(), MGF1(Sha1()), salt, 20);
        value sig2 = rsaSig2.update(message).sign();
        
        assert (sig2 == signature);
        
        value pubKey = RsaPublicKeyImpl(os2ip(e), os2ip(n));
        RsaSsaPssVerify rsaVerify = RsaSsaPssVerify(pubKey, Sha1(), MGF1(Sha1()), 20);
        rsaVerify.update(message);
        assert (rsaVerify.verify(signature));
    }
}
