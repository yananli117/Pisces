package edu.sydney.pisces;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.InteractiveArgument;
import org.cryptimeleon.craco.protocols.base.BaseProtocol;
import org.cryptimeleon.craco.protocols.base.BaseProtocolInstance;
import org.cryptimeleon.craco.protocols.base.AdHocSchnorrProof;
import org.cryptimeleon.craco.sig.ps.PSExtendedVerificationKey;
import org.cryptimeleon.craco.sig.ps.PSSignature;
import org.cryptimeleon.craco.sig.ps.PSSigningKey;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class CreditDepositProtocol extends BaseProtocol {
    private PiscesExchangeSystem pp;
    private PSExtendedVerificationKey pk1;
    private PSExtendedVerificationKey pk2;


    public CreditDepositProtocol(PiscesExchangeSystem pp, PSExtendedVerificationKey pk1, PSExtendedVerificationKey pk2) {
        super("user", "platform");
        this.pp = pp;
        this.pk1 = pk1;
        this.pk2  = pk2;
    }

    @Override
    public CreditDepositProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        if (role.equals("user"))
            return new CreditDepositProtocolInstance(((DepositCommonInput) commonInput).i, ((DepositCommonInput) commonInput).k, ((DepositCommonInput) commonInput).px, ((PiscesExchangeSystem.UserInput) secretInput).token);
        if (role.equals("platform"))
            return new CreditDepositProtocolInstance(((DepositCommonInput) commonInput).i, ((DepositCommonInput) commonInput).k, ((DepositCommonInput) commonInput).px, ((PiscesExchangeSystem.PlatfromInput2) secretInput).sk1, ((PiscesExchangeSystem.PlatfromInput2) secretInput).sk2);
        throw new IllegalArgumentException("Unknown role");
    }

    public CreditDepositProtocolInstance instantiateUser(int i, int k, int px, Token token) {
        return instantiateProtocol("user", new DepositCommonInput(i, k, px), new PiscesExchangeSystem.UserInput(token));
    }

    public CreditDepositProtocolInstance instantiatePlatform(int i, int k, int px, PSSigningKey sk1, PSSigningKey sk2) {
        return instantiateProtocol("platform", new DepositCommonInput(i, k, px), new PiscesExchangeSystem.PlatfromInput2(sk1,sk2));

    }

    public static class DepositCommonInput implements CommonInput {
        public final int i;
        public final int k;
        public final int px;
        public DepositCommonInput(int i, int k, int px) {
            this.i = i;
            this.k = k;
            this.px = px;
        }
    }

    public class CreditDepositProtocolInstance extends BaseProtocolInstance {
        private Token token;
        private PSSigningKey sk1;
        private PSSigningKey sk2;
        private int i;
        private int k;
        private int px;
        private GroupElement sigma0prime, sigma1prime;
        private GroupElement sigmacoin0, sigmacoin1;
        private CoinToken coinToken;
        private Zn.ZnElement usk, rid, cp1, cp2;
        private Zn.ZnElement rPrime;
        private Zn.ZnElement cid;
        private Zn.ZnElement r;
        private GroupElement c;

        //user instantiate this
        public CreditDepositProtocolInstance(int i, int k, int px, Token token) {
            super(CreditDepositProtocol.this, "user");
            this.i = i;
            this.k = k;
            this.px = px;
            this.token = token;
            this.usk = token.usk;
            this.rid = token.rid;
            this.cp1 = token.cp1;
            this.cp2 = token.cp2;
        }

        //platform instantiate this
        public CreditDepositProtocolInstance(int i, int k, int px, PSSigningKey sk1,PSSigningKey sk2) {
            super(CreditDepositProtocol.this, "platform");
            this.k = k;
            this.i = i;
            this.px = px;
            this.sk1 = sk1;
            this.sk2 = sk2;
        }

        @Override
        protected void doRoundForFirstRole(int round) { //user
            switch (round) {
                case 0: //send randomized signature and start proof
                    //Randomize signature
                    rPrime = pp.zp.getUniformlyRandomElement();
                    Zn.ZnElement r1 = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0prime = token.sig.getGroup1ElementSigma1().pow(r1).compute();
                    sigma1prime = token.sig.getGroup1ElementSigma2().pow(r1).op(token.sig.getGroup1ElementSigma1().pow(r1.mul(rPrime))).compute();
                    send("sigma0prime", sigma0prime.getRepresentation());
                    send("sigma1prime", sigma1prime.getRepresentation());
                    cid = pp.zp.getUniformlyRandomElement();
                    r = pp.zp.getUniformlyRandomElement();
                    c = pk2.getGroup1ElementsYi().innerProduct(RingElementVector.of(usk, cid, pp.zp.getZeroElement(), pp.zp.getZeroElement(), pp.zp.getZeroElement())).op(pk2.getGroup1ElementG().pow(r));
                    send("c", c.getRepresentation());
                    //Prove valid signature
                    runArgumentConcurrently("sigProof", getValidSignatureProof().instantiateProver(null, AdHocSchnorrProof.witnessOf(this)));
                    break;
                case 2: //send proof response
                    //Nothing to do
                    break;
                case 4:  //receive blinded signature and unblind
                    sigmacoin0 = pp.group.getG1().restoreElement(receive("sigmacoin0"));
                    sigmacoin1 = pp.group.getG1().restoreElement(receive("sigmacoin1"));
                    PSSignature sigmacoinStar = new PSSignature(sigmacoin0, sigmacoin1.op(sigmacoin0.pow(r.neg())));
                    coinToken =new CoinToken(usk,cid,pp.zp.valueOf(i),pp.zp.valueOf(k),pp.zp.valueOf(px),sigmacoinStar);
                    if (!pp.verifyCoinToken(coinToken, pk2))
                        throw new IllegalStateException("Invalid signature");
                    terminate();
                    break;
            }
        }

        @Override
        protected void doRoundForSecondRole(int round) { //platform
            switch (round) {
                case 1: //receive randomized signature and send proof challenge
                    sigma0prime = pp.group.getG1().restoreElement(receive("sigma0prime"));
                    sigma1prime = pp.group.getG1().restoreElement(receive("sigma1prime"));
                    c = pp.group.getG1().restoreElement(receive("c"));
                    runArgumentConcurrently("sigProof", getValidSignatureProof().instantiateVerifier(null));
                    break;
                case 3: //check proof (implicit) and send updated signature
                    Zn.ZnElement r = pp.zp.getUniformlyRandomNonzeroElement();
                    sigmacoin0 = pk2.getGroup1ElementG().pow(r).compute();
                    //sigmacoin1 = pk2.getGroup1ElementG().pow(sk2.getExponentX()).op(c).op(pk2.getGroup1ElementsYi().innerProduct(RingElementVector.of(pp.zp.getZeroElement(), pp.zp.getZeroElement(), i,k,px))).pow(r).compute(); //TODO optimize: precompute X
                    sigmacoin1 = pk2.getGroup1ElementG().pow(sk2.getExponentX()).op(c).op(pk2.getGroup1ElementG().pow(sk2.getExponentsYi().innerProduct(RingElementVector.of(pp.zp.getZeroElement(), pp.zp.getZeroElement(), pp.zp.valueOf(i),pp.zp.valueOf(k),pp.zp.valueOf(px))))).pow(r).compute(); //TODO optimize: precompute X
                    //System.out.println("not sure the calculation is correct");
                    send("sigmacoin0", sigmacoin0.getRepresentation());
                    send("sigmacoin1", sigmacoin1.getRepresentation());

                    terminate();
                    break;
            }
        }

        public CoinToken getUserResult() {
            return coinToken;
        }
        private InteractiveArgument getValidSignatureProof() {
            BilinearMap e = pp.group.getBilinearMap();
            if (sigma0prime.isNeutralElement())
                throw new IllegalStateException("sigma0 is the neutral group element");
            return AdHocSchnorrProof.builder(pp.zp)
                    .addLinearStatement("psVerify",
                            e.applyExpr(sigma0prime, pk1.getGroup2ElementTildeX().op(pk1.getGroup2ElementsTildeYi().expr().innerProduct(Vector.of("usk", "rid", "cp1", "cp2"))))
                                    .isEqualTo(e.applyExpr(sigma1prime.op(sigma0prime.inv().pow("rPrime")), pk1.getGroup2ElementTildeG()))
                    )
                    .addLinearStatement("psCommitOpen", c.isEqualTo(pk2.getGroup1ElementsYi().expr().innerProduct(Vector.of("usk", "cid", pp.zp.getZeroElement(), pp.zp.getZeroElement(),pp.zp.getZeroElement())).op(pk2.getGroup1ElementG().pow("r"))))
                    .buildInteractiveDamgard(pp.commitmentSchemeForDamgard);
        }
    }
}

