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

public class CoinToken implements SecretInput, Representable {
    @Represented(restorer = "zn")
    public Zn.ZnElement usk, cid, i, vi, px;
    @Represented(restorer = "pssigs")
    public PSSignature sig;

    public CoinToken(Zn zn, PSSignatureScheme pssigs, Representation repr) {
        new ReprUtil(this).register(zn, "zn").register(pssigs, "pssigs").deserialize(repr);
    }

    public CoinToken(Zn.ZnElement usk, Zn.ZnElement cid, Zn.ZnElement i, Zn.ZnElement vi, Zn.ZnElement px, PSSignature sig) {
        this.usk = usk;
        this.cid = cid;
        this.i = i;
        this.vi = vi;
        this.px = px;
        this.sig = sig;
    }

    public RingElementVector getMessageVector() {
        return new RingElementVector(usk, cid, i, vi, px);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}

