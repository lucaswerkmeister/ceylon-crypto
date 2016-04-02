import ceylon.test {
    test
}

import de.dlkw.ccrypto.impl {
    Sha1
}

class Sha1Test()
{
    test
    shared void test2b1()
    {
        value m = [#61626380, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, #18];
        value sha1 = Sha1();
        print("3 byte integer primitive");
        sha1.processIntegerChunk(m);
        print(sha1.finishedResult.collect((b)=>formatInteger(b.unsigned, 16)));
        
        print("ext use");
        sha1.reset();
        sha1.update({#61.byte, #62.byte, #63.byte});
        print(sha1.finish().collect((b)=>formatInteger(b.unsigned, 16)));
        
        value m2_0 = [
        #61626364, #62636465, #63646566, #64656667, #65666768, #66676869, #6768696a, #68696a6b,
        #696a6b6c, #6a6b6c6d, #6b6c6d6e, #6c6d6e6f, #6d6e6f70, #6e6f7071, #80000000, #00000000
        ];
        value m2_1 = [
        #00000000, #00000000, #00000000, #00000000, #00000000, #00000000, #00000000, #00000000,
        #00000000, #00000000, #00000000, #00000000, #00000000, #00000000, #00000000, #000001c0
        ];
        
        print("56 byte integer primitive");
        sha1.processIntegerChunk(m2_0);
        sha1.processIntegerChunk(m2_1);
        print(sha1.finishedResult.collect((b)=>formatInteger(b.unsigned, 16)));
        
        print("ext use");
        sha1.reset();
        sha1.update({#61.byte, #62.byte, #63.byte, #64.byte});
        sha1.update({#62.byte, #63.byte, #64.byte, #65.byte});
        sha1.update({#63.byte, #64.byte, #65.byte, #66.byte});
        sha1.update({#64.byte, #65.byte, #66.byte, #67.byte});
        sha1.update({#65.byte, #66.byte, #67.byte, #68.byte});
        sha1.update({#66.byte, #67.byte, #68.byte, #69.byte});
        sha1.update({#67.byte, #68.byte, #69.byte, #6a.byte});
        sha1.update({#68.byte, #69.byte, #6a.byte, #6b.byte});
        sha1.update({#69.byte, #6a.byte, #6b.byte, #6c.byte});
        sha1.update({#6a.byte, #6b.byte, #6c.byte, #6d.byte});
        sha1.update({#6b.byte, #6c.byte, #6d.byte, #6e.byte});
        sha1.update({#6c.byte, #6d.byte, #6e.byte, #6f.byte});
        sha1.update({#6d.byte, #6e.byte, #6f.byte, #70.byte});
        sha1.update({#6e.byte, #6f.byte, #70.byte, #71.byte});
        print(sha1.finish().collect((b)=>formatInteger(b.unsigned, 16)));
        
        print("3 byte message internal");
        sha1.processBlock({#61.byte, #62.byte, #63.byte, #80.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #18.byte});
        print(sha1.finishedResult.collect((b)=>formatInteger(b.unsigned, 16)));
        
        print("56 byte message internal");
        sha1.reset();
        sha1.processBlock({#61.byte, #62.byte, #63.byte, #64.byte
            ,#62.byte, #63.byte, #64.byte, #65.byte
        ,#63.byte, #64.byte, #65.byte, #66.byte
        ,#64.byte, #65.byte, #66.byte, #67.byte
        ,#65.byte, #66.byte, #67.byte, #68.byte
        ,#66.byte, #67.byte, #68.byte, #69.byte
        ,#67.byte, #68.byte, #69.byte, #6a.byte
        ,#68.byte, #69.byte, #6a.byte, #6b.byte
        ,#69.byte, #6a.byte, #6b.byte, #6c.byte
        ,#6a.byte, #6b.byte, #6c.byte, #6d.byte
        ,#6b.byte, #6c.byte, #6d.byte, #6e.byte
        ,#6c.byte, #6d.byte, #6e.byte, #6f.byte
        ,#6d.byte, #6e.byte, #6f.byte, #70.byte
        ,#6e.byte, #6f.byte, #70.byte, #71.byte
        ,#80.byte, #00.byte, #00.byte, #00.byte
        ,#00.byte, #00.byte, #00.byte, #00.byte});
        sha1.processBlock({
            #00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #00.byte, #00.byte
            ,#00.byte, #00.byte, #01.byte, #c0.byte});
        print(sha1.finishedResult.collect((b)=>formatInteger(b.unsigned, 16)));
    }

    test
    shared void test2_1()
    {
        //    da39a3ee5e6b4b0d3255bfef95601890afd80709
        value sha1 = Sha1();
        print(sha1.digest().collect((b)=>formatInteger(b.unsigned, 16)));
    }    
}