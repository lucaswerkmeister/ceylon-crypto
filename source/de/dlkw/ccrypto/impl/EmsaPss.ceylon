import de.dlkw.ccrypto.api {
    MessageDigester
}


Byte[8] z8 = [ 0.byte, 0.byte, 0.byte, 0.byte, 0.byte, 0.byte, 0.byte, 0.byte ];

class MessageTooLongException() extends Exception(){}
class EncodingError() extends Exception(){}
class EmsaPssSign(digester, mgf, saltGenerator, sLen, emBit)
{
    MessageDigester digester;
    digester.reset();
    
    MaskGeneratingFunction mgf;
    
    {Byte*} saltGenerator;
    
    "intended length in octets of the salt"
    Integer sLen;
    
    "maximal bit length of the integer OS2IP..."
    Integer emBit;
    Integer emLen = (emBit - 1) / 8 + 1;
    print("#SemBits: ``emBit``, emLen: ``emLen``");

    Integer hLen => digester.digestLengthOctets;
    assert (emLen >= hLen + sLen + 2);
    print("#SsLen: ``sLen``, hLen: ``hLen``");
    
    shared EmsaPssSign init()
    {
        digester.reset();
        return this;
    }
    
    throws(`class MessageTooLongException`, "the message is too long for the digester")
    shared EmsaPssSign update({Byte*} messagePart)
    {
        digester.update(messagePart);
        return this;
    }
    
    throws(`class MessageTooLongException`, "the message is too long for the digester")
    shared Byte[] finish()
    {
        Byte[] mHash = digester.digest();
        print("#SmHash:");
        hexdump(mHash);
        
        if (emLen < hLen + sLen + 2) {
            throw EncodingError();
        }

        // DON'T forget to take the sequence() of the take result
        // lest each time you access salt, another value is produced.
        Byte[] salt = saltGenerator.take(sLen).sequence();
        print("#Ssalt:");
        hexdump(salt);
        
        value mPrime = z8.chain(mHash).chain(salt);
        print("#SmPrime:");
        hexdump(mPrime);
        
        Byte[] h = digester.digest(mPrime);
        print("#Sh:");
        hexdump(h);
        
        value db = { for (i in 0:emLen - sLen - hLen - 2) 0.byte }.chain({1.byte}).chain(salt);
        print("#Sdb:");
        hexdump(db);
        
        Byte[] dbMask = mgf.mask(h, emLen - hLen - 1);
        print("#SdbMask:");
        hexdump(dbMask);
        
        value maskedDb = zipPairs(db, dbMask).map((el) => el[0].xor(el[1]));
        print("#SmaskedDb:");
        hexdump(maskedDb.sequence());
        
        Byte  maskUnusedMSBs = #ff.byte.rightLogicalShift(8 * emLen - emBit);
        print("#SmMSB: ``formatInteger(maskUnusedMSBs.unsigned, 16)``");
        assert (exists leftmostOctet = maskedDb.first?.and(maskUnusedMSBs));
        
        return maskedDb.rest.follow(leftmostOctet).chain(h).chain({ #bc.byte }).sequence();
    }
}

abstract class VerificationResult()
        of consistent | inconsistent
{}

object consistent extends VerificationResult(){}
object inconsistent extends VerificationResult(){}


class EmsaPssVerify(digester, mgf, sLen, emBits)
{
    MessageDigester digester;
    MaskGeneratingFunction mgf;
    Integer sLen;
    
    Integer emBits;
    Integer emLen = (emBits - 1) / 8 + 1;

    Integer hLen = digester.digestLengthOctets;

    Integer checkBits = 8 * emLen - emBits;
    value checkBitsMask = (1.leftLogicalShift(checkBits) - 1).leftLogicalShift(8 - checkBits).byte;
    
    variable Boolean messageWasTooLong = false;

    shared EmsaPssVerify init()
    {
        digester.reset();
        return this;
    }
    
    throws(`class MessageTooLongException`, "the message is too long for the digester")
    shared EmsaPssVerify update({Byte*} messagePart)
    {
        try {
            digester.update(messagePart);
        }
        catch (MessageTooLongException e) {
            messageWasTooLong = true;
        }
        return this;
    }
    
    shared VerificationResult verify(Byte[] em)
    {
        // 1.
        if (messageWasTooLong) {
            init();
            return inconsistent;
        }
        
        // 2.
        Byte[] mHash = digester.digest();
        print("#VmHash:");
        hexdump(mHash);

        // 3.
        if (emLen < hLen + sLen + 2) {
            init();
            return inconsistent;
        }
        
        // (precondition)
        assert (em.size == emLen);
        
        // 4.
        if (exists bc = em.last, bc == #bc.byte) {
            // good path, can this be re-formulated?
        }
        else {
            init();
            return inconsistent;
        }

        // 5.
        value maskedDb = em[0:emLen - hLen - 1];
        print("#VmaskedDb:");
        hexdump(maskedDb);

        value h = em[emLen - hLen - 1:hLen];
        print("#Vh:");
        hexdump(h);
        
        // 6.
        assert (exists mdb0 = maskedDb[0]);
        if (mdb0.and(checkBitsMask) != 0.byte) {
            init();
            return inconsistent;
        }

        // 7.
        value dbMask = mgf.mask(h, emLen - hLen - 1);
        print("#VdbMask;");
        hexdump(dbMask);
        
        // 8.
        value db = Array(zipPairs(maskedDb, dbMask).map((el) => el[0].xor(el[1])));
        print("#Vdb");
        hexdump(db);

        // 9.
        assert (exists first = db.first);
        db.set(0, first.and(checkBitsMask.not));
        
        // 10.
        if (!db[0:emLen - hLen - sLen - 2].every((b) => b == 0.byte)) {
            init();
            return inconsistent;
        }
        assert (exists b = db[emLen - hLen - sLen - 2]);
        if (b != 1.byte) {
            init();
            return inconsistent;
        }

        // 11.
        value salt = db.terminal(sLen);
        print("#Vsalt:");
        hexdump(salt);
        
        // 12.
        value mPrime = z8.chain(mHash).chain(salt);
        print("#VmPrime:");
        hexdump(mPrime);
        
        // 13.
        value hPrime = digester.digest(mPrime);
        print("#VhPrime:");
        hexdump(hPrime);
        
        return if (h == hPrime) then consistent else inconsistent;
    }
}

shared void hexdump({Byte*} b)
{
    print("``[ for (bb in b) formatInteger(bb.unsigned, 16)] ``");
}
