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
import org.cryptimeleon.math.expressions.exponent.BasicNamedExponentVariableExpr;
import org.cryptimeleon.math.structures.cartesian.Vector;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class ExchangeProtocol extends BaseProtocol {
    private PiscesExchangeSystem pp;
    private PSExtendedVerificationKey pk1;
    private PSExtendedVerificationKey pk2;
    private PSExtendedVerificationKey pk3;

    public ExchangeProtocol(PiscesExchangeSystem pp, PSExtendedVerificationKey pk1, PSExtendedVerificationKey pk2, PSExtendedVerificationKey pk3) {
        super("user", "platform");
        this.pp = pp;
        this.pk1 = pk1;
        this.pk2 = pk2;
        this.pk3 = pk3;
    }

    @Override
    public ExchangeProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        if (role.equals("user"))
            return new ExchangeProtocolInstance( ((PiscesExchangeSystem.UserInput) secretInput).ki, ((PiscesExchangeSystem.UserInput) secretInput).kj, ((PiscesExchangeSystem.UserInput) secretInput).token, ((PiscesExchangeSystem.UserInput) secretInput).coinToken, ((PiscesExchangeSystem.UserInput) secretInput).priceI, ((PiscesExchangeSystem.UserInput) secretInput).priceJ);
        if (role.equals("platform"))
            return new ExchangeProtocolInstance(((SpendCommonInput) commonInput).t, ((SpendCommonInput) commonInput).rid, ((SpendCommonInput) commonInput).cid, ((PiscesExchangeSystem.PlatformInput3) secretInput).sk1, ((PiscesExchangeSystem.PlatformInput3) secretInput).sk2, ((PiscesExchangeSystem.PlatformInput3) secretInput).sk3);
        throw new IllegalArgumentException("Unknown role");
    }


    public ExchangeProtocolInstance instantiateUser(int ki, int kj, Token token, CoinToken coinToken, PriceToken priceI, PriceToken priceJ) {
        return instantiateProtocol("user", null, new PiscesExchangeSystem.UserInput(ki,kj,token,coinToken, priceI, priceJ));
    }

    public ExchangeProtocolInstance instantiatePlatform(int t, Zn.ZnElement rid, Zn.ZnElement cid, PSSigningKey sk1, PSSigningKey sk2, PSSigningKey sk3) {
        return instantiateProtocol("platform", new SpendCommonInput(t, rid,cid), new PiscesExchangeSystem.PlatformInput3(sk1,sk2,sk3));
    }

    public static class SpendCommonInput implements CommonInput {
        public final int t;
        public final Zn.ZnElement rid;
        public final Zn.ZnElement cid;

        public SpendCommonInput(int t, Zn.ZnElement rid, Zn.ZnElement cid) {
            this.t = t;
            this.rid = rid;
            this.cid = cid;
        }
    }

    public class ExchangeProtocolInstance extends BaseProtocolInstance {
        private Token token;
        private CoinToken coiniToken,coinKiTokenUpdate;
        private CoinToken coinKjToken;
        private Token tokenUpdate;
        private PriceToken priceTokenI,priceTokenJ;
        private PSSigningKey sk1,sk2,sk3;
        private int t;
        Zn.ZnElement ki,kj;
        private Zn.ZnElement rPrimeReg;
        private Zn.ZnElement r1, r2, r3, r4,r5,r6,r7,r8;
        private Zn.ZnElement rPrimeCoini, rPrimePriceI, rPrimePriceJ;
        private GroupElement sigma0prime, sigma1prime;
        private GroupElement sigma0primeCoini, sigma1primeCoini;
        private GroupElement sigma0PriceI,sigma1PriceI;
        private GroupElement sigma0PriceJ,sigma1PriceJ;
        private GroupElement  sigma0RegUpdate,sigma1RegUpdate;
        private GroupElement  sigma0CoiniUpdate,sigma1CoiniUpdate;
        private GroupElement  sigma0Coinj,sigma1Coinj;
        private Zn.ZnElement usk;
        private Zn.ZnElement rid,cid;
        private Zn.ZnElement ridPrime,cidPrime;
        private Zn.ZnElement cidKjPrime;
        private Zn.ZnElement cp1,cp2;
        private Zn.ZnElement i,vi,pxi,pxiBar,j,pxjBar;
        private GroupElement comRegUpdate,comCoiniUpdate,comCoinj;
        private GroupElement comPxi,comPxiBar,comPxjBar, comComPxjBar,comComPxiBar;
        private GroupElement comComPxi;
        private Zn.ZnElement r9,cost,profit,r4ki,r5ki,r6kj;


        public ExchangeProtocolInstance(int ki, int kj, Token token,CoinToken coinToken, PriceToken priceTokenI, PriceToken priceTokenJ) {
            super(ExchangeProtocol.this, "user");
            assert(coinToken.i.equals(priceTokenI.i) ): "coin token should be consistent with price token ";
            this.ki = pp.zp.valueOf(ki);
            this.kj =pp.zp.valueOf(kj);
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
            this.priceTokenI = priceTokenI;
            this.priceTokenJ = priceTokenJ;
            this.pxiBar = priceTokenI.px;
            this.pxjBar = priceTokenJ.px;
            this.j = priceTokenJ.i;
        }

        public ExchangeProtocolInstance(int t, Zn.ZnElement rid, Zn.ZnElement cid, PSSigningKey sk1, PSSigningKey sk2, PSSigningKey sk3) {
            super(ExchangeProtocol.this, "platform");
            this.t = t;
            this.cid = cid;
            this.rid = rid;
            this.sk1 = sk1;
            this.sk2 = sk2;
            this.sk3 = sk3;
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

                    rPrimePriceI = pp.zp.getUniformlyRandomElement();
                    rr = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0PriceI = priceTokenI.sig.getGroup1ElementSigma1().pow(rr).compute();
                    sigma1PriceI = priceTokenI.sig.getGroup1ElementSigma2().pow(rr).op(priceTokenI.sig.getGroup1ElementSigma1().pow(rr.mul(rPrimePriceI))).compute();
                    send("sigma0PriceI", sigma0PriceI.getRepresentation());
                    send("sigma1PriceI", sigma1PriceI.getRepresentation());

                    rPrimePriceJ = pp.zp.getUniformlyRandomElement();
                    rr = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0PriceJ = priceTokenJ.sig.getGroup1ElementSigma1().pow(rr).compute();
                    sigma1PriceJ = priceTokenJ.sig.getGroup1ElementSigma2().pow(rr).op(priceTokenJ.sig.getGroup1ElementSigma1().pow(rr.mul(rPrimePriceJ))).compute();
                    send("sigma0PriceJ", sigma0PriceJ.getRepresentation());
                    send("sigma1PriceJ", sigma1PriceJ.getRepresentation());


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
                    //commit attributes of coinj
                    cidKjPrime = pp.zp.getUniformlyRandomElement();
                    r3 = pp.zp.getUniformlyRandomElement();
                    comCoinj = pk2.getGroup1ElementsYi().innerProduct(RingElementVector.of(usk, cidKjPrime, j, kj, pxjBar)).op(pk2.getGroup1ElementG().pow(r3));
                    send("comCoinj", comCoinj.getRepresentation());

                    //commit price i,iBar,jBar;
                    r4 = pp.zp.getUniformlyRandomElement();
                    comPxi = pk1.getGroup1ElementG().pow(r4).op(pk1.getGroup1ElementsYi().get(2).pow(pxi)).compute();
                    r5 = pp.zp.getUniformlyRandomElement();
                    comPxiBar = pk1.getGroup1ElementG().pow(r5).op(pk1.getGroup1ElementsYi().get(3).pow(pxiBar)).compute();
                    r6 = pp.zp.getUniformlyRandomElement();
                    comPxjBar = pk1.getGroup1ElementG().pow(r6).op(pk1.getGroup1ElementsYi().get(3).pow(pxjBar)).compute();
                    r7 = pp.zp.getUniformlyRandomElement();
                    comComPxjBar = pk1.getGroup1ElementG().pow(r7).op(comPxjBar.pow(kj)).compute();
                    r8 = pp.zp.getUniformlyRandomElement();
                    comComPxiBar = pk1.getGroup1ElementG().pow(r8).op(comPxiBar.pow(ki)).compute();
                    r9 = pp.zp.getUniformlyRandomElement();
                    comComPxi = pk1.getGroup1ElementG().pow(r9).op(comPxi.pow(ki)).compute();
                    cost = pxi.mul(ki);
                    profit = pxiBar.mul(ki);
                    r4ki = r4.mul(ki);
                    r5ki = r5.mul(ki);
                    r6kj = r6.mul(kj);
                    send("comPxi", comPxi.getRepresentation());
                    send("comPxiBar", comPxiBar.getRepresentation());
                    send("comPxjBar", comPxjBar.getRepresentation());
                    send("comComPxj", comComPxjBar.getRepresentation());
                    send("comComPxiBar", comComPxiBar.getRepresentation());
                    send("comComPxi", comComPxi.getRepresentation());
                    runArgumentConcurrently("exchangeProof", getExchangeProof().instantiateProver(null, AdHocSchnorrProof.witnessOf(this)));
                    break;

                case 2: //Proof response
                    //Nothing to do.
                    break;
                case 4: //receive blinded signature and unblind
                    sigma0RegUpdate = pp.group.getG1().restoreElement(receive("sigma0RegUpdate"));
                    sigma1RegUpdate = pp.group.getG1().restoreElement(receive("sigma1RegUpdate"));
                    sigma0CoiniUpdate = pp.group.getG1().restoreElement(receive("sigma0CoiniUpdate"));
                    sigma1CoiniUpdate = pp.group.getG1().restoreElement(receive("sigma1CoiniUpdate"));
                    sigma0Coinj = pp.group.getG1().restoreElement(receive("sigma0Coinj"));
                    sigma1Coinj = pp.group.getG1().restoreElement(receive("sigma1Coinj"));

                    PSSignature sigmaRegStar = new PSSignature(sigma0RegUpdate, sigma1RegUpdate.op(sigma0RegUpdate.pow(r1.neg())).compute());
                    tokenUpdate = new Token(usk, ridPrime, cp1.add(ki.mul(pxi)), cp2.add(ki.mul(pxiBar)), sigmaRegStar);
                    if (!pp.verifyToken(tokenUpdate, pk1))
                        throw new IllegalStateException("Invalid signature");
                    PSSignature sigmaCoini = new PSSignature(sigma0CoiniUpdate, sigma1CoiniUpdate.op(sigma0CoiniUpdate.pow(r2.neg())).compute());
                    coinKiTokenUpdate = new CoinToken(usk, cidPrime, i, vi.sub(ki), pxi, sigmaCoini);
                    if (!pp.verifyCoinToken(coinKiTokenUpdate, pk2))
                        throw new IllegalStateException("Invalid signature");
                    PSSignature sigmaCoinj = new PSSignature(sigma0Coinj, sigma1Coinj.op(sigma0Coinj.pow(r3.neg())).compute());
                    coinKjToken = new CoinToken(usk, cidKjPrime, j, kj, pxjBar, sigmaCoinj);
                    if (!pp.verifyCoinToken(coinKjToken, pk2))
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
                    sigma0PriceI = pp.group.getG1().restoreElement(receive("sigma0PriceI"));
                    sigma1PriceI = pp.group.getG1().restoreElement(receive("sigma1PriceI"));
                    sigma0PriceJ = pp.group.getG1().restoreElement(receive("sigma0PriceJ"));
                    sigma1PriceJ = pp.group.getG1().restoreElement(receive("sigma1PriceJ"));
                    comRegUpdate = pp.group.getG1().restoreElement(receive("comRegUpdate"));
                    comCoiniUpdate = pp.group.getG1().restoreElement(receive("comCoiniUpdate"));
                    comCoinj = pp.group.getG1().restoreElement(receive("comCoinj"));
                    comPxi = pp.group.getG1().restoreElement(receive("comPxi"));
                    comPxiBar = pp.group.getG1().restoreElement(receive("comPxiBar"));
                    comPxjBar = pp.group.getG1().restoreElement(receive("comPxjBar"));
                    comComPxjBar = pp.group.getG1().restoreElement(receive("comComPxj"));
                    comComPxiBar = pp.group.getG1().restoreElement(receive("comComPxiBar"));
                    comComPxi = pp.group.getG1().restoreElement(receive("comComPxi"));
                    runArgumentConcurrently("exchangeProof", getExchangeProof().instantiateVerifier(null));
                    break;

                case 3: //check proof (implicit) and send updated signature. Output dstag.
                    Zn.ZnElement rPrimeprimeprime = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0RegUpdate = pk1.getGroup1ElementG().pow(rPrimeprimeprime).compute();
                    sigma1RegUpdate = comRegUpdate.op(pk1.getGroup1ElementG().pow(sk1.getExponentX())).pow(rPrimeprimeprime).compute();

                    rPrimeprimeprime = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0CoiniUpdate = pk2.getGroup1ElementG().pow(rPrimeprimeprime).compute();
                    sigma1CoiniUpdate = comCoiniUpdate.op(pk2.getGroup1ElementG().pow(sk2.getExponentX())).pow(rPrimeprimeprime).compute();

                    rPrimeprimeprime = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0Coinj = pk2.getGroup1ElementG().pow(rPrimeprimeprime).compute();
                    sigma1Coinj = comCoinj.op(pk2.getGroup1ElementG().pow(sk2.getExponentX())).pow(rPrimeprimeprime).compute();

                    send("sigma0RegUpdate", sigma0RegUpdate.getRepresentation());
                    send("sigma1RegUpdate", sigma1RegUpdate.getRepresentation());
                    send("sigma0CoiniUpdate", sigma0CoiniUpdate.getRepresentation());
                    send("sigma1CoiniUpdate", sigma1CoiniUpdate.getRepresentation());
                    send("sigma0Coinj", sigma0Coinj.getRepresentation());
                    send("sigma1Coinj", sigma1Coinj.getRepresentation());
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

        public CoinToken getUserCoinjResult(){
            return coinKjToken;
        }

        private InteractiveArgument getExchangeProof() {
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
                            e.applyExpr(sigma0primeCoini, pk2.getGroup2ElementTildeX().op(pk2.getGroup2ElementsTildeYi().expr().innerProduct(Vector.of("usk", cid, "i", "vi","pxi"))))
                                    .isEqualTo(e.applyExpr(sigma1primeCoini.op(sigma0primeCoini.inv().pow("rPrimeCoini")), pk2.getGroup2ElementTildeG())))
                    .addLinearStatement("psPriceIVerify",
                            e.applyExpr(sigma0PriceI, pk3.getGroup2ElementTildeX().op(pk3.getGroup2ElementsTildeYi().expr().innerProduct(Vector.of( pp.zp.valueOf(t), "i", "pxiBar"))))
                                    .isEqualTo(e.applyExpr(sigma1PriceI.op(sigma0PriceI.inv().pow("rPrimePriceI")), pk3.getGroup2ElementTildeG())))
                    .addLinearStatement("psPriceJVerify",
                            e.applyExpr(sigma0PriceJ, pk3.getGroup2ElementTildeX().op(pk3.getGroup2ElementsTildeYi().expr().innerProduct(Vector.of( pp.zp.valueOf(t), "j", "pxjBar"))))
                                    .isEqualTo(e.applyExpr(sigma1PriceJ.op(sigma0PriceJ.inv().pow("rPrimePriceJ")), pk3.getGroup2ElementTildeG())))
                    .addLinearStatement("psRegCommitOpen", comRegUpdate.isEqualTo(pk1.getGroup1ElementsYi().expr().innerProduct(Vector.of("usk", "ridPrime", "cp1", "cp2")).op(pk1.getGroup1ElementG().pow("r1")).op(pk1.getGroup1ElementsYi().get(2).pow("cost")).op(pk1.getGroup1ElementsYi().get(3).pow("profit"))))
                    .addLinearStatement("ps2CommitCoiniUpdateOpen", comCoiniUpdate.isEqualTo(pk2.getGroup1ElementsYi().expr().innerProduct(Vector.of("usk", "cidPrime", "i", "vi","pxi")).op(pk2.getGroup1ElementG().pow("r2")).op(pk2.getGroup1ElementsYi().get(3).inv().pow("ki"))))
                    .addLinearStatement("ps2CommitCoinjOpen", comCoinj.isEqualTo(pk2.getGroup1ElementsYi().expr().innerProduct(Vector.of("usk", "cidKjPrime", "j", "kj","pxjBar")).op(pk2.getGroup1ElementG().pow("r3"))))
                    .addLinearStatement("commitPxi", comPxi.isEqualTo(pk1.getGroup1ElementsYi().get(2).pow("pxi").op(pk1.getGroup1ElementG().pow("r4"))))
                    .addLinearStatement("commitPxiBar", comPxiBar.isEqualTo(pk1.getGroup1ElementsYi().get(3).pow("pxiBar").op(pk1.getGroup1ElementG().pow("r5"))))
                    .addLinearStatement("commitPxjBar", comPxjBar.isEqualTo(pk1.getGroup1ElementsYi().get(3).pow("pxjBar").op(pk1.getGroup1ElementG().pow("r6"))))
                    .addLinearStatement("commitCommitPxjBar", comComPxjBar.isEqualTo(pk1.getGroup1ElementsYi().get(3).pow("profit").op(pk1.getGroup1ElementG().pow("r7")).op(pk1.getGroup1ElementG().pow("r6kj"))))
                    .addLinearStatement("commitCommitPxjBar2", comComPxjBar.isEqualTo(comPxjBar.pow("kj").op(pk1.getGroup1ElementG().pow("r7"))))
                    .addLinearStatement("commitCommitPxiBar", comComPxiBar.isEqualTo(pk1.getGroup1ElementsYi().get(3).pow("profit").op(pk1.getGroup1ElementG().pow("r8")).op(pk1.getGroup1ElementG().pow("r5ki"))))
                    .addLinearStatement("commitCommitPxiBar2", comComPxiBar.isEqualTo(comPxiBar.pow("ki").op(pk1.getGroup1ElementG().pow("r8"))))
                    .addLinearStatement("commitCommitPxi", comComPxi.isEqualTo(pk1.getGroup1ElementsYi().get(2).pow("cost").op(pk1.getGroup1ElementG().pow("r9")).op(pk1.getGroup1ElementG().pow("r4ki"))))
                    .addLinearStatement("commitCommitPxi2", comComPxi.isEqualTo(comPxi.pow("ki").op(pk1.getGroup1ElementG().pow("r9"))))
                    .addSmallerThanPowerStatement("enoughPoints", new BasicNamedExponentVariableExpr("vi").sub("ki"), pp.rangeBase, pp.rangePower, pp.setMembershipPp)
                    .buildInteractiveDamgard(pp.commitmentSchemeForDamgard);
        }
    }
}

