package edu.sydney.pisces;

import org.cryptimeleon.craco.commitment.CommitmentScheme;
import org.cryptimeleon.craco.common.plaintexts.RingElementPlainText;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.damgardtechnique.DamgardTechnique;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.setmembership.SetMembershipPublicParameters;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.ps.*;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.StandaloneRepresentable;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.zn.Zn;


public class PiscesExchangeSystem implements StandaloneRepresentable {
    @Represented
    public BilinearGroup group;
    @Represented(restorer = "group::getZn")
    public Zn zp;
    @Represented(restorer = "group::getG1")
    public GroupElement w, g,h;
    @Represented
    public PSExtendedSignatureScheme psSigs;
    @Represented
    public CommitmentScheme commitmentSchemeForDamgard;
    @Represented
    public Integer rangeBase = 256;
    @Represented
    public Integer rangePower = 8;
    @Represented(restorer = "setMembershipRestorer")
    public SetMembershipPublicParameters setMembershipPp;

    public PiscesExchangeSystem(BilinearGroup group) {
        this.group = group;
        zp = group.getZn();
        w = group.getG1().getUniformlyRandomElement().precomputePow();
        g = group.getG1().getUniformlyRandomElement().precomputePow();
        h = group.getG1().getUniformlyRandomElement().precomputePow();
        psSigs = new PSExtendedSignatureScheme(new PSPublicParameters(group));
        commitmentSchemeForDamgard = DamgardTechnique.generateCommitmentScheme(group.getG1());
        setMembershipPp = SetMembershipPublicParameters.generateInterval(group, 0, rangeBase);
    }

    public PiscesExchangeSystem(Representation repr) {
        new ReprUtil(this).register(r -> new SetMembershipPublicParameters(group, r), "setMembershipRestorer").deserialize(repr);
        w.precomputePow();
        g.precomputePow();
        h.precomputePow();
    }

    public KeyPair<GroupElement, Zn.ZnElement>  keyGen() {
        Zn.ZnElement sk = zp.getUniformlyRandomElement();
        GroupElement pk = w.pow(sk).precomputePow();
        return new KeyPair<>(pk, sk);
    }

    public SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKeyGen1() {
        return psSigs.generateKeyPair(4);
    }
    public SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKeyGen2() {
        return psSigs.generateKeyPair(5);
    }
    public SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKeyGen3() {
        return psSigs.generateKeyPair(3);
    }

    public boolean verifyToken(Token token, PSVerificationKey issuerPk) {
        Vector<RingElementPlainText> signedMessage = token.getMessageVector().map(RingElementPlainText::new);
        return psSigs.verify(issuerPk, token.sig, signedMessage);
    }
    public boolean verifyCoinToken(CoinToken coinToken, PSVerificationKey issuerPk) {
        Vector<RingElementPlainText> signedMessage = coinToken.getMessageVector().map(RingElementPlainText::new);
        return psSigs.verify(issuerPk, coinToken.sig, signedMessage);
    }
    public boolean verifyPriceToken(PriceToken priceToken, PSVerificationKey issuerPk) {
        Vector<RingElementPlainText> signedMessage = priceToken.getMessageVector().map(RingElementPlainText::new);
        return psSigs.verify(issuerPk, priceToken.sig, signedMessage);
    }
    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public static class PlatformInput implements SecretInput {
        public final PSSigningKey sk;

        public PlatformInput(PSSigningKey sk) {
            this.sk = sk;
        }
    }
    public static class PlatfromInput2 implements SecretInput {
        public final PSSigningKey sk1;
        public final PSSigningKey sk2;

        public PlatfromInput2(PSSigningKey sk1, PSSigningKey sk2) {
            this.sk1 = sk1;
            this.sk2 = sk2;
        }
    }
    public static class PlatformInput3 implements SecretInput {
        public final PSSigningKey sk1;
        public final PSSigningKey sk2;
        public final PSSigningKey sk3;

        public PlatformInput3(PSSigningKey sk1, PSSigningKey sk2, PSSigningKey sk3) {
            this.sk1 = sk1;
            this.sk2 = sk2;
            this.sk3 = sk3;
        }
    }
    public static class UserInput implements SecretInput {
        public final Zn.ZnElement usk;
        public final Token token;
        public final CoinToken coinToken;
        public PriceToken priceI, priceJ;
        public int ki,kj;

        public UserInput(Token token) {
            this.token = token;
            this.usk = token.usk;
            this.coinToken = null;
        }

        public UserInput(Token token, CoinToken coinToken) {
            this.token = token;
            this.usk = token.usk;
            this.coinToken = coinToken;
        }
        public UserInput(Zn.ZnElement usk) {
            this.usk = usk;
            this.token = null;
            this.coinToken = null;
        }
        public UserInput(int ki, int kj, Token token, CoinToken coinToken, PriceToken priceI, PriceToken priceJ) {
            assert (token.usk.equals(coinToken.usk)) : "two tokens should belong to the same user";
            this.ki = ki;
            this.kj = kj;
            this.usk = token.usk;
            this.token = token;
            this.coinToken = coinToken;
            this.priceI = priceI;
            this.priceJ = priceJ;

        }
    }
}
