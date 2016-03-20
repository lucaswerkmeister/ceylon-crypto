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

                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 8.1
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_8_1 = " 81 33 2f 4b e6 29 48 41 5e a1 d8 99 79 2e ea cf 
                  6c 6e 1d b1 da 8b e1 3b 5c ea 41 db 2f ed 46 70 
                  92 e1 ff 39 89 14 c7 14 25 97 75 f5 95 f8 54 7f 
                  73 56 92 a5 75 e6 92 3a f7 8f 22 c6 99 7d db 90 
                  fb 6f 72 d7 bb 0d d5 74 4a 31 de cd 3d c3 68 58 
                  49 83 6e d3 4a ec 59 63 04 ad 11 84 3c 4f 88 48 
                  9f 20 97 35 f5 fb 7f da f7 ce c8 ad dc 58 18 16 
                  8f 88 0a cb f4 90 d5 10 05 b7 a8 e8 4e 43 e5 42 
                  87 97 75 71 dd 99 ee a4 b1 61 eb 2d f1 f5 10 8f 
                  12 a4 14 2a 83 32 2e db 05 a7 54 87 a3 43 5c 9a 
                  78 ce 53 ed 93 bc 55 08 57 d7 a9 fb";
                   
                   //# Salt:
String salt_8_1 = "1d 65 49 1d 79 c8 64 b3 73 00 9b e6 f6 f2 46 7b 
                   ac 4c 78 fa"; 
                   
                   //# Signature:
String sig_8_1 = " 02 62 ac 25 4b fa 77 f3 c1 ac a2 2c 51 79 f8 f0 
                  40 42 2b 3c 5b af d4 0a 8f 21 cf 0f a5 a6 67 cc 
                  d5 99 3d 42 db af b4 09 c5 20 e2 5f ce 2b 1e e1 
                  e7 16 57 7f 1e fa 17 f3 da 28 05 2f 40 f0 41 9b 
                  23 10 6d 78 45 aa f0 11 25 b6 98 e7 a4 df e9 2d 
                  39 67 bb 00 c4 d0 d3 5b a3 55 2a b9 a8 b3 ee f0 
                  7c 7f ec db c5 42 4a c4 db 1e 20 cb 37 d0 b2 74 
                  47 69 94 0e a9 07 e1 7f bb ca 67 3b 20 52 23 80 
                  c5";
                   
                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 8.2
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_8_2 = " e2 f9 6e af 0e 05 e7 ba 32 6e cc a0 ba 7f d2 f7 
                  c0 23 56 f3 ce de 9d 0f aa bf 4f cc 8e 60 a9 73 
                  e5 59 5f d9 ea 08"; 
                   
                   //# Salt:
String salt_8_2 = "43 5c 09 8a a9 90 9e b2 37 7f 12 48 b0 91 b6 89 
                   87 ff 18 38"; 
                   
                   //# Signature:
String sig_8_2 = "27 07 b9 ad 51 15 c5 8c 94 e9 32 e8 ec 0a 28 0f 
                  56 33 9e 44 a1 b5 8d 4d dc ff 2f 31 2e 5f 34 dc 
                  fe 39 e8 9c 6a 94 dc ee 86 db bd ae 5b 79 ba 4e 
                  08 19 a9 e7 bf d9 d9 82 e7 ee 6c 86 ee 68 39 6e 
                  8b 3a 14 c9 c8 f3 4b 17 8e b7 41 f9 d3 f1 21 10 
                  9b f5 c8 17 2f ad a2 e7 68 f9 ea 14 33 03 2c 00 
                  4a 8a a0 7e b9 90 00 0a 48 dc 94 c8 ba c8 aa be 
                  2b 09 b1 aa 46 c0 a2 aa 0e 12 f6 3f bb a7 75 ba 
                  7e"; 
                   
                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 8.3
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_8_3 = " e3 5c 6e d9 8f 64 a6 d5 a6 48 fc ab 8a db 16 33 
                  1d b3 2e 5d 15 c7 4a 40 ed f9 4c 3d c4 a4 de 79 
                  2d 19 08 89 f2 0f 1e 24 ed 12 05 4a 6b 28 79 8f 
                  cb 42 d1 c5 48 76 9b 73 4c 96 37 31 42 09 2a ed 
                  27 76 03 f4 73 8d f4 dc 14 46 58 6d 0e c6 4d a4 
                  fb 60 53 6d b2 ae 17 fc 7e 3c 04 bb fb bb d9 07 
                  bf 11 7c 08 63 6f a1 6f 95 f5 1a 62 16 93 4d 3e 
                  34 f8 50 30 f1 7b bb c5 ba 69 14 40 58 af f0 81 
                  e0 b1 9c f0 3c 17 19 5c 5e 88 8b a5 8f 6f e0 a0 
                  2e 5c 3b da 97 19 a7"; 
                   
                   //# Salt:
String salt_8_3 = "c6 eb be 76 df 0c 4a ea 32 c4 74 17 5b 2f 13 68 
                   62 d0 45 29"; 
                   
                   //# Signature:
String sig_8_3 = " 2a d2 05 09 d7 8c f2 6d 1b 6c 40 61 46 08 6e 4b 
                  0c 91 a9 1c 2b d1 64 c8 7b 96 6b 8f aa 42 aa 0c 
                  a4 46 02 23 23 ba 4b 1a 1b 89 70 6d 7f 4c 3b e5 
                  7d 7b 69 70 2d 16 8a b5 95 5e e2 90 35 6b 8c 4a 
                  29 ed 46 7d 54 7e c2 3c ba df 28 6c cb 58 63 c6 
                  67 9d a4 67 fc 93 24 a1 51 c7 ec 55 aa c6 db 40 
                  84 f8 27 26 82 5c fe 1a a4 21 bc 64 04 9f b4 2f 
                  23 14 8f 9c 25 b2 dc 30 04 37 c3 8d 42 8a a7 5f 
                  96"; 
                   
                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 8.4
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_8_4 = " db c5 f7 50 a7 a1 4b e2 b9 3e 83 8d 18 d1 4a 86 
                  95 e5 2e 8a dd 9c 0a c7 33 b8 f5 6d 27 47 e5 29 
                  a0 cc a5 32 dd 49 b9 02 ae fe d5 14 44 7f 9e 81 
                  d1 61 95 c2 85 38 68 cb 9b 30 f7 d0 d4 95 c6 9d 
                  01 b5 c5 d5 0b 27 04 5d b3 86 6c 23 24 a4 4a 11 
                  0b 17 17 74 6d e4 57 d1 c8 c4 5c 3c d2 a9 29 70 
                  c3 d5 96 32 05 5d 4c 98 a4 1d 6e 99 e2 a3 dd d5 
                  f7 f9 97 9a b3 cd 18 f3 75 05 d2 51 41 de 2a 1b 
                  ff 17 b3 a7 dc e9 41 9e cc 38 5c f1 1d 72 84 0f 
                  19 95 3f d0 50 92 51 f6 ca fd e2 89 3d 0e 75 c7 
                  81 ba 7a 50 12 ca 40 1a 4f a9 9e 04 b3 c3 24 9f 
                  92 6d 5a fe 82 cc 87 da b2 2c 3c 1b 10 5d e4 8e 
                  34 ac e9 c9 12 4e 59 59 7a c7 eb f8"; 
                   
                   //# Salt:
String salt_8_4 = "02 1f dc c6 eb b5 e1 9b 1c b1 6e 9c 67 f2 76 81 
                   65 7f e2 0a"; 
                   
                   //# Signature:
String sig_8_4 = " 1e 24 e6 e5 86 28 e5 17 50 44 a9 eb 6d 83 7d 48 
                  af 12 60 b0 52 0e 87 32 7d e7 89 7e e4 d5 b9 f0 
                  df 0b e3 e0 9e d4 de a8 c1 45 4f f3 42 3b b0 8e 
                  17 93 24 5a 9d f8 bf 6a b3 96 8c 8e dd c3 b5 32 
                  85 71 c7 7f 09 1c c5 78 57 69 12 df eb d1 64 b9 
                  de 54 54 fe 0b e1 c1 f6 38 5b 32 83 60 ce 67 ec 
                  7a 05 f6 e3 0e b4 5c 17 c4 8a c7 00 41 d2 ca b6 
                  7f 0a 2a e7 aa fd cc 8d 24 5e a3 44 2a 63 00 cc 
                  c7"; 
                   
                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 8.5
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_8_5 = " 04 dc 25 1b e7 2e 88 e5 72 34 85 b6 38 3a 63 7e 
                  2f ef e0 76 60 c5 19 a5 60 b8 bc 18 bd ed b8 6e 
                  ae 23 64 ea 53 ba 9d ca 6e b3 d2 e7 d6 b8 06 af 
                  42 b3 e8 7f 29 1b 4a 88 81 d5 bf 57 2c c9 a8 5e 
                  19 c8 6a cb 28 f0 98 f9 da 03 83 c5 66 d3 c0 f5 
                  8c fd 8f 39 5d cf 60 2e 5c d4 0e 8c 71 83 f7 14 
                  99 6e 22 97 ef"; 
                   
                   //# Salt:
String salt_8_5 = "c5 58 d7 16 7c bb 45 08 ad a0 42 97 1e 71 b1 37 
                   7e ea 42 69"; 
                   
                   //# Signature:
String sig_8_5 = " 33 34 1b a3 57 6a 13 0a 50 e2 a5 cf 86 79 22 43 
                  88 d5 69 3f 5a cc c2 35 ac 95 ad d6 8e 5e b1 ee 
                  c3 16 66 d0 ca 7a 1c da 6f 70 a1 aa 76 2c 05 75 
                  2a 51 95 0c db 8a f3 c5 37 9f 18 cf e6 b5 bc 55 
                  a4 64 82 26 a1 5e 91 2e f1 9a d7 7a de ea 91 1d 
                  67 cf ef d6 9b a4 3f a4 11 91 35 ff 64 21 17 ba 
                  98 5a 7e 01 00 32 5e 95 19 f1 ca 6a 92 16 bd a0 
                  55 b5 78 50 15 29 11 25 e9 0d cd 07 a2 ca 96 73 
                  ee";
                   
                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 8.6
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_8_6 = " 0e a3 7d f9 a6 fe a4 a8 b6 10 37 3c 24 cf 39 0c 
                  20 fa 6e 21 35 c4 00 c8 a3 4f 5c 18 3a 7e 8e a4 
                  c9 ae 09 0e d3 17 59 f4 2d c7 77 19 cc a4 00 ec 
                  dc c5 17 ac fc 7a c6 90 26 75 b2 ef 30 c5 09 66 
                  5f 33 21 48 2f c6 9a 9f b5 70 d1 5e 01 c8 45 d0 
                  d8 e5 0d 2a 24 cb f1 cf 0e 71 49 75 a5 db 7b 18 
                  d9 e9 e9 cb 91 b5 cb 16 86 90 60 ed 18 b7 b5 62 
                  45 50 3f 0c af 90 35 2b 8d e8 1c b5 a1 d9 c6 33 
                  60 92 f0 cd "; 
                   
                   //# Salt:
String salt_8_6 = "76 fd 4e 64 fd c9 8e b9 27 a0 40 3e 35 a0 84 e7 
                   6b a9 f9 2a";
                   
                   //# Signature:
String sig_8_6 = " 1e d1 d8 48 fb 1e db 44 12 9b d9 b3 54 79 5a f9 
                  7a 06 9a 7a 00 d0 15 10 48 59 3e 0c 72 c3 51 7f 
                  f9 ff 2a 41 d0 cb 5a 0a c8 60 d7 36 a1 99 70 4f 
                  7c b6 a5 39 86 a8 8b bd 8a bc c0 07 6a 2c e8 47 
                  88 00 31 52 5d 44 9d a2 ac 78 35 63 74 c5 36 e3 
                  43 fa a7 cb a4 2a 5a aa 65 06 08 77 91 c0 6a 8e 
                  98 93 35 ae d1 9b fa b2 d5 e6 7e 27 fb 0c 28 75 
                  af 89 6c 21 b6 e8 e7 30 9d 04 e4 f6 72 7e 69 46 
                  3e";

 [[Byte[], Byte[], Byte[]]*] messages1031 = [
    [conv(msg_8_1), conv(salt_8_1), conv(sig_8_1)],
    [conv(msg_8_2), conv(salt_8_2), conv(sig_8_2)],
    [conv(msg_8_3), conv(salt_8_3), conv(sig_8_3)],
    [conv(msg_8_4), conv(salt_8_4), conv(sig_8_4)],
    [conv(msg_8_5), conv(salt_8_5), conv(sig_8_5)],
    [conv(msg_8_6), conv(salt_8_6), conv(sig_8_6)]
];

class TestVectors1031()
{
    test
    parameters(`value messages1031`)
    shared void example1(Byte[] message, Byte[] salt, Byte[] signature)
    {
        // ==================================
        // Example 1: A 1025-bit RSA Key Pair
        // ==================================
                
        // ------------------------------
        // Components of the RSA Key Pair
        // ------------------------------
        
        // RSA modulus n:
        // omitted, equals p*q

        // RSA public exponent e:
        value eS = "01 00 01";
        
        // RSA private exponent d:
        value dS = "6c 66 ff e9 89 80 c3 8f cd ea b5 15 98 98 83 61 
                    65 f4 b4 b8 17 c4 f6 a8 d4 86 ee 4e a9 13 0f e9 
                    b9 09 2b d1 36 d1 84 f9 5f 50 4a 60 7e ac 56 58 
                    46 d2 fd d6 59 7a 89 67 c7 39 6e f9 5a 6e ee bb 
                    45 78 a6 43 96 6d ca 4d 8e e3 de 84 2d e6 32 79 
                    c6 18 15 9c 1a b5 4a 89 43 7b 6a 61 20 e4 93 0a 
                    fb 52 a4 ba 6c ed 8a 49 47 ac 64 b3 0a 34 97 cb 
                    e7 01 c2 d6 26 6d 51 72 19 ad 0e c6 d3 47 db e9";
        
        // Prime p:
         value pS = "08 da d7 f1 13 63 fa a6 23 d5 d6 d5 e8 a3 19 32 
                     8d 82 19 0d 71 27 d2 84 6c 43 9b 0a b7 26 19 b0 
                     a4 3a 95 32 0e 4e c3 4f c3 a9 ce a8 76 42 23 05 
                     bd 76 c5 ba 7b e9 e2 f4 10 c8 06 06 45 a1 d2 9e 
                     db"; 
         
         //# Prime q: 
         value qS = "08 47 e7 32 37 6f c7 90 0f 89 8e a8 2e b2 b0 fc 
                     41 85 65 fd ae 62 f7 d9 ec 4c e2 21 7b 97 99 0d 
                     d2 72 db 15 7f 99 f6 3c 0d cb b9 fb ac db d4 c4 
                     da db 6d f6 77 56 35 8c a4 17 48 25 b4 8f 49 70 
                     6d"; 
         
         //# p's CRT exponent dP: 
         value dPS = "05 c2 a8 3c 12 4b 36 21 a2 aa 57 ea 2c 3e fe 03 
                      5e ff 45 60 f3 3d de bb 7a da b8 1f ce 69 a0 c8 
                      c2 ed c1 65 20 dd a8 3d 59 a2 3b e8 67 96 3a c6 
                      5f 2c c7 10 bb cf b9 6e e1 03 de b7 71 d1 05 fd 
                      85"; 
         
         //# q's CRT exponent dQ: 
         value dQS = "04 ca e8 aa 0d 9f aa 16 5c 87 b6 82 ec 14 0b 8e 
                      d3 b5 0b 24 59 4b 7a 3b 2c 22 0b 36 69 bb 81 9f 
                      98 4f 55 31 0a 1a e7 82 36 51 d4 a0 2e 99 44 79 
                      72 59 51 39 36 34 34 e5 e3 0a 7e 7d 24 15 51 e1 
                      b9";
         
         //# CRT coefficient qInv: 
         value qInvS = "07 d3 e4 7b f6 86 60 0b 11 ac 28 3c e8 8d bb 3f 
                        60 51 e8 ef d0 46 80 e4 4c 17 1e f5 31 b8 0b 2b 
                        7c 39 fc 76 63 20 e2 cf 15 d8 d9 98 20 e9 6f f3 
                        0d c6 96 91 83 9c 4b 40 d7 b0 6e 45 30 7d c9 1f 
                        3f";         

        value e = conv(eS);
        value d = conv(dS);
        value p = conv(pS);
        value q = conv(qS); 
        value dP = conv(dPS); 
        value dQ = conv(dQS); 
        value qInv = conv(qInvS); 
           
        value nW = os2ip(p) * os2ip(q);
        
        value privKey1 = RsaCrtPrivateKeyImpl(os2ip(p), os2ip(q), os2ip(dP), os2ip(dQ), os2ip(qInv));
        RsaSsaPssSign rsaSig1 = RsaSsaPssSign(privKey1, Sha1(), MGF1(Sha1()), salt, 20);
        value sig1 = rsaSig1.update(message).sign();
        
        assert (sig1 == signature);
        
        value privKey2 = RsaExponentPrivateKeyImpl(os2ip(d), nW);
        RsaSsaPssSign rsaSig2 = RsaSsaPssSign(privKey2, Sha1(), MGF1(Sha1()), salt, 20);
        value sig2 = rsaSig2.update(message).sign();
        
        assert (sig2 == signature);
        
        value pubKey = RsaPublicKeyImpl(os2ip(e), nW);
        RsaSsaPssVerify rsaVerify = RsaSsaPssVerify(pubKey, Sha1(), MGF1(Sha1()), 20);
        rsaVerify.update(message);
        assert (rsaVerify.verify(signature));
    }
}
