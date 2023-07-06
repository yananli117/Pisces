package edu.sydney.pisces;


import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.InteractiveArgument;
import org.cryptimeleon.craco.protocols.base.AdHocSchnorrProof;
import org.cryptimeleon.craco.protocols.base.BaseProtocol;
import org.cryptimeleon.craco.protocols.base.BaseProtocolInstance;
import org.cryptimeleon.craco.sig.ps.PSExtendedVerificationKey;
import org.cryptimeleon.craco.sig.ps.PSSignature;
import org.cryptimeleon.craco.sig.ps.PSSigningKey;
import org.cryptimeleon.math.expressions.exponent.BasicNamedExponentVariableExpr;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class WithdrawProtocol extends BaseProtocol {
    private PiscesExchangeSystem pp;
    private PSExtendedVerificationKey pk1;
    private PSExtendedVerificationKey pk2;

    public WithdrawProtocol(PiscesExchangeSystem pp, PSExtendedVerificationKey pk1, PSExtendedVerificationKey pk2) {
        super("user", "platform");
        this.pp = pp;
        this.pk1 = pk1;
        this.pk2 = pk2;
    }

    @Override
    public WithdrawProtocol.WithdrawProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        if (role.equals("user"))
            return new WithdrawProtocol.WithdrawProtocolInstance( ((WithdrawCommonInput) commonInput).k,((WithdrawCommonInput) commonInput).px, ((PiscesExchangeSystem.UserInput) secretInput).token, ((PiscesExchangeSystem.UserInput) secretInput).coinToken);
        if (role.equals("platform"))
            return new WithdrawProtocol.WithdrawProtocolInstance(((WithdrawCommonInput2) commonInput).i,((WithdrawCommonInput2) commonInput).k,  ((WithdrawCommonInput2) commonInput).px, ((WithdrawCommonInput2) commonInput).t, ((WithdrawCommonInput2) commonInput).rid, ((WithdrawCommonInput2) commonInput).cid, ((PiscesExchangeSystem.PlatfromInput2) secretInput).sk1, ((PiscesExchangeSystem.PlatfromInput2) secretInput).sk2);
        throw new IllegalArgumentException("Unknown role");
    }

    public WithdrawProtocol.WithdrawProtocolInstance instantiateUser(int ki, int px, Token token, CoinToken coinToken) {
        return instantiateProtocol("user", new WithdrawCommonInput(ki,px), new PiscesExchangeSystem.UserInput(token,coinToken));
    }

    public WithdrawProtocol.WithdrawProtocolInstance instantiatePlatform(int i, int k, int px, int t, Zn.ZnElement rid, Zn.ZnElement cid, PSSigningKey sk1, PSSigningKey sk2) {
        return instantiateProtocol("platform", new WithdrawCommonInput2(i,k,px,t,rid,cid), new PiscesExchangeSystem.PlatfromInput2(sk1,sk2));
    }

    public static class WithdrawCommonInput2 implements CommonInput {
        public final int t;
        public final Zn.ZnElement rid;
        public final Zn.ZnElement cid;
        public final int i;
        public final int k;
        public final int px;

        public WithdrawCommonInput2(int i, int k, int px,int t, Zn.ZnElement rid, Zn.ZnElement cid) {
            this.t = t;
            this.rid = rid;
            this.cid = cid;
            this.i = i;
            this.k = k;
            this.px = px;
        }
    }

    public static class WithdrawCommonInput implements CommonInput {
        public final int k;
        public final int px;
        public WithdrawCommonInput( int k, int px) {
            this.k = k;
            this.px = px;
        }
    }

    public class WithdrawProtocolInstance extends BaseProtocolInstance {
        private Token token;
        private CoinToken coiniToken,coinKiTokenUpdate;
        private Token tokenUpdate;
        private PSSigningKey sk1,sk2;
        private int t;
        Zn.ZnElement ki;
        private Zn.ZnElement rPrimeReg;
        private Zn.ZnElement r1, r2, r4;
        private Zn.ZnElement rPrimeCoini;
        private GroupElement sigma0prime, sigma1prime;
        private GroupElement sigma0primeCoini, sigma1primeCoini;
        private GroupElement  sigma0RegUpdate,sigma1RegUpdate;
        private GroupElement  sigma0CoiniUpdate,sigma1CoiniUpdate;
        private Zn.ZnElement usk;
        private Zn.ZnElement rid,cid;
        private Zn.ZnElement ridPrime,cidPrime;
        private Zn.ZnElement cp1,cp2;
        private Zn.ZnElement i,vi,pxi,pxiBar;
        private GroupElement comRegUpdate,comCoiniUpdate;
        private GroupElement comPxi;
        private GroupElement comComPxi;
        private Zn.ZnElement r9,profit;
        private Zn.ZnElement cost, r4ki;

        public WithdrawProtocolInstance(int ki, int px, Token token,CoinToken coinToken) {
            super(WithdrawProtocol.this, "user");

            this.ki = pp.zp.valueOf(ki);
            this.token = token;
            this.usk = token.usk;
            this.rid = token.rid;
            this.cp1 = token.cp1;
            this.cp2 = token.cp2;
            this.coiniToken = coinToken;
            this.cid = coinToken.cid;
            this.i = coinToken.i;
            this.vi = coinToken.vi;
            this.pxi = coinToken.px;
            this.pxiBar = pp.zp.valueOf(px);
            this.profit = this.pxiBar.mul(this.ki);
        }

        public WithdrawProtocolInstance(int idx,int ki,  int px, int t, Zn.ZnElement rid, Zn.ZnElement cid, PSSigningKey sk1, PSSigningKey sk2) {
            super(WithdrawProtocol.this, "platform");
            this.ki = pp.zp.valueOf(ki);
            this.i = pp.zp.valueOf(idx);
            this.pxiBar = pp.zp.valueOf(px);
            this.t = t;
            this.cid = cid;
            this.rid = rid;
            this.sk1 = sk1;
            this.sk2 = sk2;
            this.profit = this.pxiBar.mul(this.ki);
        }

        @Override
        protected void doRoundForFirstRole(int round) { //user
            switch (round) {

                case 0:
                    //randomize and commit reg-token
                    rPrimeReg = pp.zp.getUniformlyRandomElement();
                    Zn.ZnElement rr = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0prime = token.sig.getGroup1ElementSigma1().pow(rr).compute();
                    sigma1prime = token.sig.getGroup1ElementSigma2().pow(rr).op(token.sig.getGroup1ElementSigma1().pow(rr.mul(rPrimeReg))).compute();
                    send("sigma0prime", sigma0prime.getRepresentation());
                    send("sigma1prime", sigma1prime.getRepresentation());

                    //randomize and commit i-coin-token
                    rPrimeCoini = pp.zp.getUniformlyRandomElement();
                    rr = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0primeCoini = coiniToken.sig.getGroup1ElementSigma1().pow(rr).compute();
                    sigma1primeCoini = coiniToken.sig.getGroup1ElementSigma2().pow(rr).op(coiniToken.sig.getGroup1ElementSigma1().pow(rr.mul(rPrimeCoini))).compute();
                    send("sigma0primeCoini", sigma0primeCoini.getRepresentation());
                    send("sigma1primeCoini", sigma1primeCoini.getRepresentation());

                    //commit attributes of regUpdate
                    ridPrime = pp.zp.getUniformlyRandomElement();
                    r1 = pp.zp.getUniformlyRandomElement();
                    comRegUpdate = pk1.getGroup1ElementsYi().innerProduct(RingElementVector.of(usk, ridPrime, cp1.add(pxi.mul(ki)), cp2.add(pxiBar.mul(ki)))).op(pk1.getGroup1ElementG().pow(r1));
                    send("comRegUpdate", comRegUpdate.getRepresentation());

                    //commit attributes of coiniUpdate
                    cidPrime = pp.zp.getUniformlyRandomElement();
                    r2 = pp.zp.getUniformlyRandomElement();
                    comCoiniUpdate = pk2.getGroup1ElementsYi().innerProduct(RingElementVector.of(usk, cidPrime, i, vi.sub(ki),pxi)).op(pk2.getGroup1ElementG().pow(r2));
                    send("comCoiniUpdate", comCoiniUpdate.getRepresentation());

                    //commit price i,iBar,jBar;
                    r4 = pp.zp.getUniformlyRandomElement();
                    comPxi = pk1.getGroup1ElementG().pow(r4).op(pk1.getGroup1ElementsYi().get(2).pow(pxi)).compute();
                    r9 = pp.zp.getUniformlyRandomElement();
                    comComPxi = pk1.getGroup1ElementG().pow(r9).op(comPxi.pow(ki)).compute();
                    cost = pxi.mul(ki);
                    r4ki = r4.mul(ki);

                    send("comPxi", comPxi.getRepresentation());
                    send("comComPxi", comComPxi.getRepresentation());
                    runArgumentConcurrently("withdrawProof", getWithdrawProof().instantiateProver(null, AdHocSchnorrProof.witnessOf(this)));
                    break;

                case 2: //Proof response
                    //Nothing to do.
                    break;
                case 4: //receive blinded signature and unblind
                    sigma0RegUpdate = pp.group.getG1().restoreElement(receive("sigma0RegUpdate"));
                    sigma1RegUpdate = pp.group.getG1().restoreElement(receive("sigma1RegUpdate"));
                    sigma0CoiniUpdate = pp.group.getG1().restoreElement(receive("sigma0CoiniUpdate"));
                    sigma1CoiniUpdate = pp.group.getG1().restoreElement(receive("sigma1CoiniUpdate"));

                    PSSignature sigmaRegStar = new PSSignature(sigma0RegUpdate, sigma1RegUpdate.op(sigma0RegUpdate.pow(r1.neg())).compute());
                    tokenUpdate = new Token(usk, ridPrime, cp1.add(ki.mul(pxi)), cp2.add(ki.mul(pxiBar)), sigmaRegStar);
                    if (!pp.verifyToken(tokenUpdate, pk1))
                        throw new IllegalStateException("Invalid signature");
                    PSSignature sigmaCoini = new PSSignature(sigma0CoiniUpdate, sigma1CoiniUpdate.op(sigma0CoiniUpdate.pow(r2.neg())).compute());
                    coinKiTokenUpdate = new CoinToken(usk, cidPrime, i, vi.sub(ki), pxi, sigmaCoini);
                    if (!pp.verifyCoinToken(coinKiTokenUpdate, pk2))
                        throw new IllegalStateException("Invalid signature");

                    terminate();
                    break;
            }
        }

        @Override
        protected void doRoundForSecondRole(int round) { //platform
            switch (round) {

                case 1: //Receive stuff and send proof challenge
                    sigma0prime = pp.group.getG1().restoreElement(receive("sigma0prime"));
                    sigma1prime = pp.group.getG1().restoreElement(receive("sigma1prime"));
                    sigma0primeCoini = pp.group.getG1().restoreElement(receive("sigma0primeCoini"));
                    sigma1primeCoini = pp.group.getG1().restoreElement(receive("sigma1primeCoini"));

                    comRegUpdate = pp.group.getG1().restoreElement(receive("comRegUpdate"));
                    comCoiniUpdate = pp.group.getG1().restoreElement(receive("comCoiniUpdate"));
                    comPxi = pp.group.getG1().restoreElement(receive("comPxi"));
                    comComPxi = pp.group.getG1().restoreElement(receive("comComPxi"));
                    runArgumentConcurrently("withdrawProof", getWithdrawProof().instantiateVerifier(null));
                    break;

                case 3: //check proof (implicit) and send updated signature. Output dstag.
                    Zn.ZnElement rPrimeprimeprime = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0RegUpdate = pk1.getGroup1ElementG().pow(rPrimeprimeprime).compute();
                    sigma1RegUpdate = comRegUpdate.op(pk1.getGroup1ElementG().pow(sk1.getExponentX())).pow(rPrimeprimeprime).compute();

                    rPrimeprimeprime = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0CoiniUpdate = pk2.getGroup1ElementG().pow(rPrimeprimeprime).compute();
                    sigma1CoiniUpdate = comCoiniUpdate.op(pk2.getGroup1ElementG().pow(sk2.getExponentX())).pow(rPrimeprimeprime).compute();

                    send("sigma0RegUpdate", sigma0RegUpdate.getRepresentation());
                    send("sigma1RegUpdate", sigma1RegUpdate.getRepresentation());
                    send("sigma0CoiniUpdate", sigma0CoiniUpdate.getRepresentation());
                    send("sigma1CoiniUpdate", sigma1CoiniUpdate.getRepresentation());

                    terminate();
                    break;
            }
        }

        public Token getUserResult() {
            return tokenUpdate;
        }
        public CoinToken getUserCoiniResult(){
            return coinKiTokenUpdate;
        }

        private InteractiveArgument getWithdrawProof() {
            BilinearMap e = pp.group.getBilinearMap();
            //neutral element is the identity element
            if (sigma0prime.isNeutralElement())
                throw new IllegalStateException("sigma0 is the neutral group element");
            if (sigma0primeCoini.isNeutralElement())
                throw new IllegalStateException("sigma0Coini is the neutral group element");
            return AdHocSchnorrProof.builder(pp.zp)
                    .addLinearStatement("psVerify",
                            e.applyExpr(sigma0prime, pk1.getGroup2ElementTildeX().op(pk1.getGroup2ElementsTildeYi().expr().innerProduct(Vector.of("usk", rid, "cp1", "cp2"))))
                                    .isEqualTo(e.applyExpr(sigma1prime.op(sigma0prime.inv().pow("rPrimeReg")), pk1.getGroup2ElementTildeG())))
                    .addLinearStatement("ps2Verify",
                            e.applyExpr(sigma0primeCoini, pk2.getGroup2ElementTildeX().op(pk2.getGroup2ElementsTildeYi().expr().innerProduct(Vector.of("usk", cid, i, "vi","pxi"))))
                                    .isEqualTo(e.applyExpr(sigma1primeCoini.op(sigma0primeCoini.inv().pow("rPrimeCoini")), pk2.getGroup2ElementTildeG())))
                    .addLinearStatement("psRegCommitOpen", comRegUpdate.isEqualTo(pk1.getGroup1ElementsYi().expr().innerProduct(Vector.of("usk", "ridPrime", "cp1", "cp2")).op(pk1.getGroup1ElementG().pow("r1")).op(pk1.getGroup1ElementsYi().get(2).pow("cost")).op(pk1.getGroup1ElementsYi().get(3).pow(profit))))
                    .addLinearStatement("ps2CommitCoiniUpdateOpen", comCoiniUpdate.isEqualTo(pk2.getGroup1ElementsYi().expr().innerProduct(Vector.of("usk", "cidPrime", i, "vi","pxi")).op(pk2.getGroup1ElementG().pow("r2")).op(pk2.getGroup1ElementsYi().get(3).inv().pow(ki))))
                    .addLinearStatement("commitPxi", comPxi.isEqualTo(pk1.getGroup1ElementsYi().get(2).pow("pxi").op(pk1.getGroup1ElementG().pow("r4"))))
                    .addLinearStatement("commitCommitPxi", comComPxi.isEqualTo(pk1.getGroup1ElementsYi().get(2).pow("cost").op(pk1.getGroup1ElementG().pow("r9")).op(pk1.getGroup1ElementG().pow("r4ki"))))
                    .addSmallerThanPowerStatement("enoughPoints", new BasicNamedExponentVariableExpr("vi").sub(ki), pp.rangeBase, pp.rangePower, pp.setMembershipPp)
                    .buildInteractiveDamgard(pp.commitmentSchemeForDamgard);
        }
    }
}
