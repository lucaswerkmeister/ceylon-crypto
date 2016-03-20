class ObjectIdentifier
{
    Integer n;
    shared new (Integer n, ObjectIdentifier? prefix = null)
    {
        this.n = n;
    }
}

object iso extends ObjectIdentifier(1){}
object identified_organization extends ObjectIdentifier(3, iso){}
object oiw extends ObjectIdentifier(14, identified_organization){}
object secsig extends ObjectIdentifier(3, oiw){}
object algorithms extends ObjectIdentifier(2, secsig){}
object id_sha1 extends ObjectIdentifier(26, algorithms){}