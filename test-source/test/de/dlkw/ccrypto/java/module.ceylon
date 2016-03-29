native("jvm") module test.de.dlkw.ccrypto.java "1.0.0" {
    shared import de.dlkw.ccrypto.impl "0.0.2";
    import ceylon.test "1.2.2";
    
    shared import java.base "7";
    import ceylon.interop.java "1.2.2";
    import ceylon.random "1.2.2";
    import oracle.jdk.base "7";
}
