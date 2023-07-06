package edu.sydney.pisces;

public class KeyPair <PK, SK> {
    public final PK pk;
    public final SK sk;

    public KeyPair(PK pk, SK sk) {
        this.pk = pk;
        this.sk = sk;
    }
}

