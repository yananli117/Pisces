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

public class PriceToken implements SecretInput, Representable {
    @Represented(restorer = "zn")
    public Zn.ZnElement t, i, px;
    @Represented(restorer = "pssigs")
    public PSSignature sig;

    public PriceToken(Zn zn, PSSignatureScheme pssigs, Representation repr) {
        new ReprUtil(this).register(zn, "zn").register(pssigs, "pssigs").deserialize(repr);
    }

    public PriceToken( Zn.ZnElement t, Zn.ZnElement i, Zn.ZnElement px, PSSignature sig) {

        this.i = i;
        this.t = t;
        this.px = px;
        this.sig = sig;
    }

    public RingElementVector getMessageVector() {
        return new RingElementVector(t, i, px);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}


