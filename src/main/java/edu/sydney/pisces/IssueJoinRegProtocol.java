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
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class IssueJoinRegProtocol extends BaseProtocol {
    private PiscesExchangeSystem pp;
    private PSExtendedVerificationKey pk;

    public IssueJoinRegProtocol(PiscesExchangeSystem pp, PSExtendedVerificationKey pk) {
        super("user", "platform");
        this.pp = pp;
        this.pk = pk;
    }

    @Override
    public IssueJoinRegProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        if (role.equals("user"))
            return new IssueJoinRegProtocolInstance(((IssueCommonInput) commonInput).upk, ((PiscesExchangeSystem.UserInput) secretInput).usk);
        if (role.equals("platform"))
            return new IssueJoinRegProtocolInstance(((IssueCommonInput) commonInput).upk, ((PiscesExchangeSystem.PlatformInput) secretInput).sk);
        throw new IllegalArgumentException("Unknown role");
    }

    public IssueJoinRegProtocolInstance instantiateUser(GroupElement upk, Zn.ZnElement usk) {
        return instantiateProtocol("user", new IssueCommonInput(upk), new PiscesExchangeSystem.UserInput(usk));
    }

    public IssueJoinRegProtocolInstance instantiatePlatform(GroupElement upk, PSSigningKey sk) {
        return instantiateProtocol("platform", new IssueCommonInput(upk), new PiscesExchangeSystem.PlatformInput(sk));
    }

    public static class IssueCommonInput implements CommonInput {
        public final GroupElement upk;

        public IssueCommonInput(GroupElement upk) {
            this.upk = upk;
        }
    }

    public class IssueJoinRegProtocolInstance extends BaseProtocolInstance {
        private GroupElement upk;
        private Zn.ZnElement usk;
        private PSSigningKey sk;
        private Zn.ZnElement rid;
        private Zn.ZnElement r;
        private GroupElement c;
        private GroupElement sigma0prime, sigma1prime;
        private Token token;

        public IssueJoinRegProtocolInstance(GroupElement upk, Zn.ZnElement usk) {
            super(IssueJoinRegProtocol.this, "user");
            this.upk = upk;
            this.usk = usk;
        }

        public IssueJoinRegProtocolInstance(GroupElement upk, PSSigningKey sk) {
            super(IssueJoinRegProtocol.this, "platform");
            this.upk = upk;
            this.sk = sk;
        }
        @Override
        protected void doRoundForFirstRole(int round) { //user
            switch (round) {
                case 0: //commit to user share of dsid
                    rid = pp.zp.getUniformlyRandomElement();
                    r = pp.zp.getUniformlyRandomElement();
                    c = pk.getGroup1ElementsYi().innerProduct(RingElementVector.of(usk, rid, pp.zp.getZeroElement(),pp.zp.getZeroElement())).op(pk.getGroup1ElementG().pow(r));
                    send("c", c.getRepresentation());
                    runArgumentConcurrently("wellFormednessProof", getWellFormednessProof().instantiateProver(null, AdHocSchnorrProof.witnessOf(this)));
                    break;
                case 2: //prove well-formedness (response)
                    break;
                case 4: //receive blinded signature and unblind
                    sigma0prime = pp.group.getG1().restoreElement(receive("sigma0prime"));
                    sigma1prime = pp.group.getG1().restoreElement(receive("sigma1prime")).op(sigma0prime.pow(r.neg()));
                    token = new Token(usk, rid, pp.zp.getZeroElement(), pp.zp.getZeroElement(), new PSSignature(sigma0prime, sigma1prime));
                    if (!pp.verifyToken(token, pk))
                        throw new IllegalStateException("Invalid token");
                    terminate();
                    break;
            }
        }

        @Override
        protected void doRoundForSecondRole(int round) { //platform
            switch (round) {
                case 1: //check well-formedness (send challenge)
                    c = pp.group.getG1().restoreElement(receive("c"));
                    runArgumentConcurrently("wellFormednessProof", getWellFormednessProof().instantiateVerifier(null));
                    break;
                case 3: //check well-formedness (got last message). Send signature if valid.
                    //Check happens implicitly
                    //Signature:
                    Zn.ZnElement r = pp.zp.getUniformlyRandomNonzeroElement();
                    sigma0prime = pk.getGroup1ElementG().pow(r).compute();
                    sigma1prime = pk.getGroup1ElementG().pow(sk.getExponentX()).op(c).pow(r).compute(); //TODO optimize: precompute X
                    send("sigma0prime", sigma0prime.getRepresentation());
                    send("sigma1prime", sigma1prime.getRepresentation());
                    terminate();
                    break;
            }
        }
        public Token getUserResult() {
            return token;
        }

        private InteractiveArgument getWellFormednessProof() {
            return AdHocSchnorrProof.builder(pp.zp)
                    .addLinearStatement("psCommitOpen", c.isEqualTo(pk.getGroup1ElementsYi().expr().innerProduct(Vector.of("usk", "rid", pp.zp.getZeroElement(), pp.zp.getZeroElement())).op(pk.getGroup1ElementG().pow("r"))))
                    .addLinearStatement("upkWellFormed",  upk.isEqualTo(pp.w.pow("usk")))
                    .buildInteractiveDamgard(pp.commitmentSchemeForDamgard);
        }
    }
}

