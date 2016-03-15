import ceylon.test {
    test,
    parameters
}

import de.dlkw.ccrypto {
    RsaCrtPrivateKey,
    RsaSsaPssSign,
    os2ip,
    RsaSsaPssVerify,
    RsaPublicKey,
    RsaExponentPrivateKey
}

                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 2.1
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_2_1 = " da ba 03 20 66 26 3f ae db 65 98 48 11 52 78 a5 
                   2c 44 fa a3 a7 6f 37 51 5e d3 36 32 10 72 c4 0a 
                   9d 9b 53 bc 05 01 40 78 ad f5 20 87 51 46 aa e7 
                   0f f0 60 22 6d cb 7b 1f 1f c2 7e 93 60";
                   
                   //# Salt:
String salt_2_1 = "57 bf 16 0b cb 02 bb 1d c7 28 0c f0 45 85 30 b7 
                   d2 83 2f f7"; 
                   
                   //# Signature:
String sig_2_1 = " 01 4c 5b a5 33 83 28 cc c6 e7 a9 0b f1 c0 ab 3f 
                   d6 06 ff 47 96 d3 c1 2e 4b 63 9e d9 13 6a 5f ec 
                   6c 16 d8 88 4b dd 99 cf dc 52 14 56 b0 74 2b 73 
                   68 68 cf 90 de 09 9a db 8d 5f fd 1d ef f3 9b a4 
                   00 7a b7 46 ce fd b2 2d 7d f0 e2 25 f5 46 27 dc 
                   65 46 61 31 72 1b 90 af 44 53 63 a8 35 8b 9f 60 
                   76 42 f7 8f ab 0a b0 f4 3b 71 68 d6 4b ae 70 d8 
                   82 78 48 d8 ef 1e 42 1c 57 54 dd f4 2c 25 89 b5 
                   b3";
                   
                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 2.2
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_2_2 = " e4 f8 60 1a 8a 6d a1 be 34 44 7c 09 59 c0 58 57 
                   0c 36 68 cf d5 1d d5 f9 cc d6 ad 44 11 fe 82 13 
                   48 6d 78 a6 c4 9f 93 ef c2 ca 22 88 ce bc 2b 9b 
                   60 bd 04 b1 e2 20 d8 6e 3d 48 48 d7 09 d0 32 d1 
                   e8 c6 a0 70 c6 af 9a 49 9f cf 95 35 4b 14 ba 61 
                   27 c7 39 de 1b b0 fd 16 43 1e 46 93 8a ec 0c f8 
                   ad 9e b7 2e 83 2a 70 35 de 9b 78 07 bd c0 ed 8b 
                   68 eb 0f 5a c2 21 6b e4 0c e9 20 c0 db 0e dd d3 
                   86 0e d7 88 ef ac ca ca 50 2d 8f 2b d6 d1 a7 c1 
                   f4 1f f4 6f 16 81 c8 f1 f8 18 e9 c4 f6 d9 1a 0c 
                   78 03 cc c6 3d 76 a6 54 4d 84 3e 08 4e 36 3b 8a 
                   cc 55 aa 53 17 33 ed b5 de e5 b5 19 6e 9f 03 e8 
                   b7 31 b3 77 64 28 d9 e4 57 fe 3f bc b3 db 72 74 
                   44 2d 78 58 90 e9 cb 08 54 b6 44 4d ac e7 91 d7 
                   27 3d e1 88 97 19 33 8a 77 fe"; 
                   
                   //# Salt:
String salt_2_2 = "7f 6d d3 59 e6 04 e6 08 70 e8 98 e4 7b 19 bf 2e 
                   5a 7b 2a 90"; 
                   
                   //# Signature:
String sig_2_2 = " 01 09 91 65 6c ca 18 2b 7f 29 d2 db c0 07 e7 ae 
                   0f ec 15 8e b6 75 9c b9 c4 5c 5f f8 7c 76 35 dd 
                   46 d1 50 88 2f 4d e1 e9 ae 65 e7 f7 d9 01 8f 68 
                   36 95 4a 47 c0 a8 1a 8a 6b 6f 83 f2 94 4d 60 81 
                   b1 aa 7c 75 9b 25 4b 2c 34 b6 91 da 67 cc 02 26 
                   e2 0b 2f 18 b4 22 12 76 1d cd 4b 90 8a 62 b3 71 
                   b5 91 8c 57 42 af 4b 53 7e 29 69 17 67 4f b9 14 
                   19 47 61 62 1c c1 9a 41 f6 fb 95 3f bc bb 64 9d 
                   ea"; 
                   
                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 2.3
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_2_3 = " 52 a1 d9 6c 8a c3 9e 41 e4 55 80 98 01 b9 27 a5 
                   b4 45 c1 0d 90 2a 0d cd 38 50 d2 2a 66 d2 bb 07 
                   03 e6 7d 58 67 11 45 95 aa bf 5a 7a eb 5a 8f 87 
                   03 4b bb 30 e1 3c fd 48 17 a9 be 76 23 00 23 60 
                   6d 02 86 a3 fa f8 a4 d2 2b 72 8e c5 18 07 9f 9e 
                   64 52 6e 3a 0c c7 94 1a a3 38 c4 37 99 7c 68 0c 
                   ca c6 7c 66 bf a1"; 
                   
                   //# Salt:
String salt_2_3 = "fc a8 62 06 8b ce 22 46 72 4b 70 8a 05 19 da 17 
                   e6 48 68 8c"; 
                   
                   //# Signature:
String sig_2_3 = " 00 7f 00 30 01 8f 53 cd c7 1f 23 d0 36 59 fd e5 
                   4d 42 41 f7 58 a7 50 b4 2f 18 5f 87 57 85 20 c3 
                   07 42 af d8 43 59 b6 e6 e8 d3 ed 95 9d c6 fe 48 
                   6b ed c8 e2 cf 00 1f 63 a7 ab e1 62 56 a1 b8 4d 
                   f0 d2 49 fc 05 d3 19 4c e5 f0 91 27 42 db bf 80 
                   dd 17 4f 6c 51 f6 ba d7 f1 6c f3 36 4e ba 09 5a 
                   06 26 7d c3 79 38 03 ac 75 26 ae be 0a 47 5d 38 
                   b8 c2 24 7a b5 1c 48 98 df 70 47 dc 6a df 52 c6 
                   c4"; 
                   
                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 2.4
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_2_4 = " a7 18 2c 83 ac 18 be 65 70 a1 06 aa 9d 5c 4e 3d 
                   bb d4 af ae b0 c6 0c 4a 23 e1 96 9d 79 ff"; 
                   
                   //# Salt:
String salt_2_4 = "80 70 ef 2d e9 45 c0 23 87 68 4b a0 d3 30 96 73 
                   22 35 d4 40"; 
                   
                   //# Signature:
String sig_2_4 = " 00 9c d2 f4 ed be 23 e1 23 46 ae 8c 76 dd 9a d3 
                   23 0a 62 07 61 41 f1 6c 15 2b a1 85 13 a4 8e f6 
                   f0 10 e0 e3 7f d3 df 10 a1 ec 62 9a 0c b5 a3 b5 
                   d2 89 30 07 29 8c 30 93 6a 95 90 3b 6b a8 55 55 
                   d9 ec 36 73 a0 61 08 fd 62 a2 fd a5 6d 1c e2 e8 
                   5c 4d b6 b2 4a 81 ca 3b 49 6c 36 d4 fd 06 eb 7c 
                   91 66 d8 e9 48 77 c4 2b ea 62 2b 3b fe 92 51 fd 
                   c2 1d 8d 53 71 ba da d7 8a 48 82 14 79 63 35 b4 
                   0b"; 
                   
                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 2.5
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_2_5 = " 86 a8 3d 4a 72 ee 93 2a 4f 56 30 af 65 79 a3 86 
                   b7 8f e8 89 99 e0 ab d2 d4 90 34 a4 bf c8 54 dd 
                   94 f1 09 4e 2e 8c d7 a1 79 d1 95 88 e4 ae fc 1b 
                   1b d2 5e 95 e3 dd 46 1f"; 
                   
                   //# Salt:
String salt_2_5 = "17 63 9a 4e 88 d7 22 c4 fc a2 4d 07 9a 8b 29 c3 
                   24 33 b0 c9"; 
                   
                   //# Signature:
String sig_2_5 = " 00 ec 43 08 24 93 1e bd 3b aa 43 03 4d ae 98 ba 
                   64 6b 8c 36 01 3d 16 71 c3 cf 1c f8 26 0c 37 4b 
                   19 f8 e1 cc 8d 96 50 12 40 5e 7e 9b f7 37 86 12 
                   df cc 85 fc e1 2c da 11 f9 50 bd 0b a8 87 67 40 
                   43 6c 1d 25 95 a6 4a 1b 32 ef cf b7 4a 21 c8 73 
                   b3 cc 33 aa f4 e3 dc 39 53 de 67 f0 67 4c 04 53 
                   b4 fd 9f 60 44 06 d4 41 b8 16 09 8c b1 06 fe 34 
                   72 bc 25 1f 81 5f 59 db 2e 43 78 a3 ad dc 18 1e 
                   cf";
                   
                   //# --------------------------------
                   //# RSASSA-PSS Signature Example 2.6
                   //# --------------------------------
                   
                   //# Message to be signed:
String msg_2_6 = " 04 9f 91 54 d8 71 ac 4a 7c 7a b4 53 25 ba 75 45 
                   a1 ed 08 f7 05 25 b2 66 7c f1"; 
                   
                   //# Salt:
String salt_2_6 = "37 81 0d ef 10 55 ed 92 2b 06 3d f7 98 de 5d 0a 
                   ab f8 86 ee";
                   
                   //# Signature:
String sig_2_6 = " 00 47 5b 16 48 f8 14 a8 dc 0a bd c3 7b 55 27 f5 
                   43 b6 66 bb 6e 39 d3 0e 5b 49 d3 b8 76 dc cc 58 
                   ea c1 4e 32 a2 d5 5c 26 16 01 44 56 ad 2f 24 6f 
                   c8 e3 d5 60 da 3d df 37 9a 1c 0b d2 00 f1 02 21 
                   df 07 8c 21 9a 15 1b c8 d4 ec 9d 2f c2 56 44 67 
                   81 10 14 ef 15 d8 ea 01 c2 eb bf f8 c2 c8 ef ab 
                   38 09 6e 55 fc be 32 85 c7 aa 55 88 51 25 4f af 
                   fa 92 c1 c7 2b 78 75 86 63 ef 45 82 84 31 39 d7 
                   a6";

 [[Byte[], Byte[], Byte[]]*] messages1025 = [
    [conv(msg_2_1), conv(salt_2_1), conv(sig_2_1)],
    [conv(msg_2_2), conv(salt_2_2), conv(sig_2_2)],
    [conv(msg_2_3), conv(salt_2_3), conv(sig_2_3)],
    [conv(msg_2_4), conv(salt_2_4), conv(sig_2_4)],
    [conv(msg_2_5), conv(salt_2_5), conv(sig_2_5)],
    [conv(msg_2_6), conv(salt_2_6), conv(sig_2_6)]
];

class TestVectors1025()
{
    test
    parameters(`value messages1025`)
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
        value dS = "02 7d 14 7e 46 73 05 73 77 fd 1e a2 01 56 57 72 
                    17 6a 7d c3 83 58 d3 76 04 56 85 a2 e7 87 c2 3c 
                    15 57 6b c1 6b 9f 44 44 02 d6 bf c5 d9 8a 3e 88 
                    ea 13 ef 67 c3 53 ec a0 c0 dd ba 92 55 bd 7b 8b 
                    b5 0a 64 4a fd fd 1d d5 16 95 b2 52 d2 2e 73 18 
                    d1 b6 68 7a 1c 10 ff 75 54 5f 3d b0 fe 60 2d 5f 
                    2b 7f 29 4e 36 01 ea b7 b9 d1 ce cd 76 7f 64 69 
                    2e 3e 53 6c a2 84 6c b0 c2 dd 48 6a 39 fa 75 b1";
        
        // Prime p:
         value pS = "01 66 01 e9 26 a0 f8 c9 e2 6e ca b7 69 ea 65 a5 
                     e7 c5 2c c9 e0 80 ef 51 94 57 c6 44 da 68 91 c5 
                     a1 04 d3 ea 79 55 92 9a 22 e7 c6 8a 7a f9 fc ad 
                     77 7c 3c cc 2b 9e 3d 36 50 bc e4 04 39 9b 7e 59 
                     d1"; 
         
         //# Prime q: 
         value qS = "01 4e af a1 d4 d0 18 4d a7 e3 1f 87 7d 12 81 dd 
                     da 62 56 64 86 9e 83 79 e6 7a d3 b7 5e ae 74 a5 
                     80 e9 82 7a bd 6e b7 a0 02 cb 54 11 f5 26 67 97 
                     76 8f b8 e9 5a e4 0e 3e 8a 01 f3 5f f8 9e 56 c0 
                     79"; 
         
         //# p's CRT exponent dP: 
         value dPS = "e2 47 cc e5 04 93 9b 8f 0a 36 09 0d e2 00 93 87 
                      55 e2 44 4b 29 53 9a 7d a7 a9 02 f6 05 68 35 c0 
                      db 7b 52 55 94 97 cf e2 c6 1a 80 86 d0 21 3c 47 
                      2c 78 85 18 00 b1 71 f6 40 1d e2 e9 c2 75 6f 31"; 
         
         //# q's CRT exponent dQ: 
         value dQS = "b1 2f ba 75 78 55 e5 86 e4 6f 64 c3 8a 70 c6 8b 
                      3f 54 8d 93 d7 87 b3 99 99 9d 4c 8f 0b bd 25 81 
                      c2 1e 19 ed 00 18 a6 d5 d3 df 86 42 4b 3a bc ad 
                      40 19 9d 31 49 5b 61 30 9f 27 c1 bf 55 d4 87 c1";
         
         //# CRT coefficient qInv: 
         value qInvS = "56 4b 1e 1f a0 03 bd a9 1e 89 09 04 25 aa c0 5b 
                        91 da 9e e2 50 61 e7 62 8d 5f 51 30 4a 84 99 2f 
                        dc 33 76 2b d3 78 a5 9f 03 0a 33 4d 53 2b d0 da 
                        e8 f2 98 ea 9e d8 44 63 6a d5 fb 8c bd c0 3c ad";         

        value e = conv(eS);
        value d = conv(dS);
        value p = conv(pS);
        value q = conv(qS); 
        value dP = conv(dPS); 
        value dQ = conv(dQS); 
        value qInv = conv(qInvS); 
           
        value nW = os2ip(p) * os2ip(q);
        
        value privKey1 = RsaCrtPrivateKey(os2ip(p), os2ip(q), os2ip(dP), os2ip(dQ), os2ip(qInv));
        RsaSsaPssSign rsaSig1 = RsaSsaPssSign(privKey1, salt);
        value sig1 = rsaSig1.update(message).finish();
        
        assert (sig1 == signature);
        
        value privKey2 = RsaExponentPrivateKey(os2ip(d), nW);
        RsaSsaPssSign rsaSig2 = RsaSsaPssSign(privKey2, salt);
        value sig2 = rsaSig2.update(message).finish();
        
        assert (sig2 == signature);
        
        value pubKey = RsaPublicKey(os2ip(e), nW);
        RsaSsaPssVerify rsaVerify = RsaSsaPssVerify(pubKey);
        rsaVerify.update(message);
        assert (rsaVerify.verify(signature));
    }
}
