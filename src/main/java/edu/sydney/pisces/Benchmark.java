package edu.sydney.pisces;

import org.cryptimeleon.craco.protocols.TwoPartyProtocolInstance;
import org.cryptimeleon.craco.sig.SignatureKeyPair;
import org.cryptimeleon.craco.sig.ps.PSExtendedVerificationKey;
import org.cryptimeleon.craco.sig.ps.PSSignature;
import org.cryptimeleon.craco.sig.ps.PSSigningKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.debug.DebugBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;
import org.cryptimeleon.math.structures.rings.cartesian.RingElementVector;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.mclwrap.bn254.MclBilinearGroup;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.*;

class LogFormatter extends Formatter {
    @Override
    public String format(LogRecord record) {
        Date date = new Date();
        String sDate = date.toString();
        return "[" + sDate + "]" + "[" + record.getLevel() + "]"
                + record.getClass() + record.getMessage() + "\n";
    }

}
public class Benchmark {
    static Logger log = Logger.getLogger("uacstesglog");
    static {
        log.setLevel(Level.ALL);
        FileHandler fileHandler = null;
        try {
            fileHandler = new FileHandler("uacstestlog.log");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        fileHandler.setLevel(Level.ALL);
        fileHandler.setFormatter(new LogFormatter());
        log.addHandler(fileHandler);
    }

    PiscesExchangeSystem exchangeSystem;
    KeyPair<GroupElement, Zn.ZnElement> userKey;
    SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKey1;
    SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKey2;
    SignatureKeyPair<PSExtendedVerificationKey, PSSigningKey> issuerKey3;
    Token token;
    CoinToken coinToken;
    HashMap<Integer, PriceToken> priceTokenMap;
    long userTime, platformTime;
    long currentPhaseStart;
    int userMessageLength;
    int platformMessageLength;
    boolean isLengthCount = false;

    public void setup(BilinearGroup bilinearGroup) {
        exchangeSystem = new PiscesExchangeSystem(bilinearGroup);
        issuerKey1 = exchangeSystem.issuerKeyGen1();
        issuerKey2 = exchangeSystem.issuerKeyGen2();
        issuerKey3 = exchangeSystem.issuerKeyGen3();
        userKey = exchangeSystem.keyGen();
        priceTokenMap = new HashMap<>();
        priceTokenMap.put(1,generatePriceToken(100, 1,  50));
        priceTokenMap.put(2,generatePriceToken(100, 2,  10));
        priceTokenMap.put(3,generatePriceToken(100, 3,  100));
        priceTokenMap.put(4,generatePriceToken(100, 4,  20));
        priceTokenMap.put(5,generatePriceToken(100, 5,  200));
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private PriceToken generatePriceToken(int t, int i, int px){
        GroupElement sigma0, sigma1;
        Zn.ZnElement rPrime = exchangeSystem.zp.getUniformlyRandomNonzeroElement();
        sigma0 = issuerKey3.getVerificationKey().getGroup1ElementG().pow(rPrime).compute();
        sigma1 = sigma0.pow(issuerKey3.getSigningKey().getExponentsYi().innerProduct(RingElementVector.of(exchangeSystem.zp.valueOf(t), exchangeSystem.zp.valueOf(i), exchangeSystem.zp.valueOf(px)))).op(sigma0.pow(issuerKey3.getSigningKey().getExponentX())).compute();
        PSSignature sigmaPriceiBar = new PSSignature(sigma0, sigma1);
        PriceToken priceToken = new PriceToken(exchangeSystem.zp.valueOf(t), exchangeSystem.zp.valueOf(i), exchangeSystem.zp.valueOf(px), sigmaPriceiBar);
        if (!exchangeSystem.verifyPriceToken(priceToken, issuerKey3.getVerificationKey()))
            throw new IllegalStateException("Invalid signature");
        return priceToken;
    }

    /**
     * run Join procedure
     *  user joins the Pisces system, and gets a registration token
     */
    public void join() {
        //Set up user
        countTowards(true);
        startStopwatch();
        IssueJoinRegProtocol protocol = new IssueJoinRegProtocol(exchangeSystem, issuerKey1.getVerificationKey());
        IssueJoinRegProtocol.IssueJoinRegProtocolInstance userInstance = protocol.instantiateUser(userKey.pk, userKey.sk);
        addTimeToUser();

        //Set up platform
        countTowards(false);
        startStopwatch();
        IssueJoinRegProtocol protocol2 = new IssueJoinRegProtocol(exchangeSystem, issuerKey1.getVerificationKey());
        IssueJoinRegProtocol.IssueJoinRegProtocolInstance platformInstance = protocol2.instantiatePlatform(userKey.pk, issuerKey1.getSigningKey());
        addTimeToPlatform();

        //Run protocol
        runProtocol(userInstance, platformInstance);

        startStopwatch();
        countTowards(true);
        token = userInstance.getUserResult();
        token.getRepresentation();
        addTimeToUser();
    }

    /**
     * run deposit procedure
     *  user deposit coin#i with amount k and price px
     */
    public void deposit(int i, int k, int px) {
        //Set up user
        countTowards(true);
        startStopwatch();
        CreditDepositProtocol depositProtocol = new CreditDepositProtocol(exchangeSystem, issuerKey1.getVerificationKey(), issuerKey2.getVerificationKey());
        CreditDepositProtocol.CreditDepositProtocolInstance depositUserInstance = depositProtocol.instantiateUser(i,k,px, token);
        addTimeToUser();

        //Set up platform
        countTowards(false);
        startStopwatch();
        CreditDepositProtocol depositProtocol2 = new CreditDepositProtocol(exchangeSystem, issuerKey1.getVerificationKey(), issuerKey2.getVerificationKey());
        CreditDepositProtocol.CreditDepositProtocolInstance depositPlatformInstance = depositProtocol2.instantiatePlatform(i,k,px, issuerKey1.getSigningKey(),issuerKey2.getSigningKey());
        addTimeToPlatform();

        runProtocol(depositUserInstance, depositPlatformInstance);

        countTowards(true);
        startStopwatch();
        coinToken = depositUserInstance.getUserResult();
        coinToken.getRepresentation();
        addTimeToUser();
    }

    /**
     * run exchange procedure
     * user exchange coin#ki with amount i to coin#kj with amount j,
     * the prices follow the current price shown in the platform via priceTokens
     */
    public void exchange(int ki, int kj, int i, int j ) {
        //Set up user
        countTowards(true);
        startStopwatch();
        ExchangeProtocol exchangeProtocol = new ExchangeProtocol(exchangeSystem, issuerKey1.getVerificationKey(),issuerKey2.getVerificationKey(), issuerKey3.getVerificationKey());
        ExchangeProtocol.ExchangeProtocolInstance spendUserInstance = exchangeProtocol.instantiateUser(ki,kj, token,coinToken,priceTokenMap.get(i), priceTokenMap.get(j));
        addTimeToUser();

        countTowards(false);
        startStopwatch();
        ExchangeProtocol exchangeProtocol2 = new ExchangeProtocol(exchangeSystem, issuerKey1.getVerificationKey(),issuerKey2.getVerificationKey(), issuerKey3.getVerificationKey());
        ExchangeProtocol.ExchangeProtocolInstance exchangePlatformInstance = exchangeProtocol2.instantiatePlatform(100, token.rid, coinToken.cid, issuerKey1.getSigningKey(), issuerKey2.getSigningKey(), issuerKey3.getSigningKey());
        addTimeToPlatform();

        runProtocol(spendUserInstance, exchangePlatformInstance);

        countTowards(true);
        startStopwatch();
        token = spendUserInstance.getUserResult();
        token.getRepresentation();
        coinToken = spendUserInstance.getUserCoiniResult();
        coinToken.getRepresentation();
        CoinToken coinjToken = spendUserInstance.getUserCoinjResult();
        coinjToken.getRepresentation();
        addTimeToUser();

        countTowards(false);
        startStopwatch();
        addTimeToPlatform();
    }

    /**
     * run withdrawal procedure
     *user withdraw coin#idx with amount ki and price px
     */
    public void withdraw(int idx, int ki, int px) {
        //Set up user
        countTowards(true);
        startStopwatch();
        WithdrawProtocol withdrawProtocol = new WithdrawProtocol(exchangeSystem, issuerKey1.getVerificationKey(),issuerKey2.getVerificationKey());
        WithdrawProtocol.WithdrawProtocolInstance withdrawUserInstance = withdrawProtocol.instantiateUser(ki,px, token,coinToken);
        addTimeToUser();

        countTowards(false);
        startStopwatch();
        WithdrawProtocol withdrawProtocol2 = new WithdrawProtocol(exchangeSystem, issuerKey1.getVerificationKey(),issuerKey2.getVerificationKey());
        WithdrawProtocol.WithdrawProtocolInstance withdrawPlatformInstance = withdrawProtocol2.instantiatePlatform(idx,ki,px,100, token.rid, coinToken.cid, issuerKey1.getSigningKey(), issuerKey2.getSigningKey());
        addTimeToPlatform();

        runProtocol(withdrawUserInstance, withdrawPlatformInstance);

        countTowards(true);
        startStopwatch();
        token = withdrawUserInstance.getUserResult();
        token.getRepresentation();
        coinToken = withdrawUserInstance.getUserCoiniResult();
        coinToken.getRepresentation();
        addTimeToUser();

        countTowards(false);
        startStopwatch();
        addTimeToPlatform();
    }

    public void runProtocol(TwoPartyProtocolInstance userInstance, TwoPartyProtocolInstance platformInstance) {
        boolean isUsersTurn = userInstance.sendsFirstMessage();
        TwoPartyProtocolInstance currentParty = isUsersTurn ? userInstance : platformInstance;
        Representation message = null;
        int userComLength = 0;
        int platformComLength =0;

        do {
            countTowards(isUsersTurn);
            startStopwatch();
            message = currentParty.nextMessage(message);
            addTimeTo(isUsersTurn);
            //count and print message length
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(bos);
                oos.writeObject(message);
                //System.out.println("serialized message length: "+ bos.toByteArray().length);
                if (isUsersTurn ) {
                    userComLength += bos.toByteArray().length;
                    //System.out.println(message);
                } else {
                    platformComLength += bos.toByteArray().length;
                }
                oos.flush();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            isUsersTurn = !isUsersTurn;
            currentParty = isUsersTurn ? userInstance : platformInstance;
        } while (!userInstance.hasTerminated() || !platformInstance.hasTerminated());
        countMessageLength(userComLength, platformComLength);
    }

    void countMessageLength(int userLength, int platformLength){
        if (!isLengthCount) {
            userMessageLength = userLength;
            platformMessageLength = platformLength;
            isLengthCount = true;
        }
    }
    public void countTowards(boolean toUser) {
        if (exchangeSystem.group instanceof DebugBilinearGroup) {
            ((DebugBilinearGroup) exchangeSystem.group).setBucket(toUser ? "user" : "platform");
        }
    }
    public void startStopwatch() {
        currentPhaseStart = System.nanoTime();
    }
    public void addTimeTo(boolean toUser) {
        if (toUser)
            addTimeToUser();
        else
            addTimeToPlatform();
    }
    public void addTimeToUser() {
        userTime += System.nanoTime() - currentPhaseStart;
    }
    public void addTimeToPlatform() {
        platformTime += System.nanoTime() - currentPhaseStart;
    }
    public void resetTimes() {
        userTime = 0;
        platformTime = 0;
    }
    public void printTimes(int numberIterations) {
        log.info("User time: "+userTime/numberIterations/1000000 + "ms per iteration");
        log.info("Platform time: "+ platformTime /numberIterations/1000000 + "ms per iteration");
    }

    public static void main(String[] args) throws IOException {
        //System.out.println(System.getProperty("java.library.path"));
        log.info("This is test java util log");
        try {
            Benchmark benchmark = new Benchmark();
            benchmark.setup(new MclBilinearGroup());
            int iterations = 100;
            log.info("Iteration: "+ iterations );

            benchmark.resetTimes();
            for (int i = 0; i < iterations; i++)
                benchmark.join();
            log.info("\nJoin/Register procedure:");
            benchmark.printTimes(iterations);
            log.info("User communication byte Length: "+ benchmark.userMessageLength  );
            log.info("Platform communication byte Length: "+ benchmark.platformMessageLength);
            benchmark.isLengthCount = false;

            benchmark.resetTimes();
            for (int i = 0; i < iterations; i++)
                benchmark.deposit(1, 50000,10 );
            log.info("\nDeposit Coin#1, Amount 50000, Price 10:");
            benchmark.printTimes(iterations);
            log.info("User communication byte Length: "+ benchmark.userMessageLength );
            log.info("Platform communication byte Length: "+ benchmark.platformMessageLength);
            benchmark.isLengthCount = false;

            benchmark.resetTimes();
            for (int i = 0; i < iterations; i++)
                benchmark.exchange(20,50, 1,4);
            log.info("\nExchange coin#1 to coin#4 with amount 20 to 50:");
            benchmark.printTimes(iterations);
            log.info("User communication byte Length: "+ benchmark.userMessageLength );
            log.info("Platform communication byte Length: "+ benchmark.platformMessageLength);
            benchmark.isLengthCount = false;

            benchmark.resetTimes();
            for (int i = 0; i < iterations; i++)
                benchmark.withdraw(1,2, 50);
            log.info("\nWithdraw coin#1, amount 2, price 50:");
            benchmark.printTimes(iterations);
            log.info("User communication byte Length: "+ benchmark.userMessageLength );
            log.info("Platform communication byte Length: "+ benchmark.platformMessageLength);

        } catch (RuntimeException e) {
            e.printStackTrace();
        }

    }
}


