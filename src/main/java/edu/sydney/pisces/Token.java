package edu.sydney.pisces;


import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.sig.ps.PSSignature;
import org.cryptimeleon.craco.sig.ps.PSSignatureScheme;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class Token implements SecretInput, Representable {
    @Represented(restorer = "zn")
    public Zn.ZnElement usk, rid, cp1, cp2;
    @Represented(restorer = "pssigs")
    public PSSignature sig;

    public Token(Zn zn, PSSignatureScheme pssigs, Representation repr) {
        new ReprUtil(this).register(zn, "zn").register(pssigs, "pssigs").deserialize(repr);
    }

    public Token(Zn.ZnElement usk, Zn.ZnElement rid, Zn.ZnElement cp1, Zn.ZnElement cp2, PSSignature sig) {
        this.usk = usk;
        this.rid = rid;
        this.cp1 = cp1;
        this.cp2 = cp2;
        this.sig = sig;
    }

    public RingElementVector getMessageVector() {
        return new RingElementVector(usk, rid, cp1, cp2);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}

