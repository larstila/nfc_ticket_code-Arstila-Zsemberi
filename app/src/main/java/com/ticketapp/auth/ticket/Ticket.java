package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {
    private static final String APP_ID = TicketActivity.outer.getString(R.string.app_id);
    private static final String APP_VERSION = TicketActivity.outer.getString(R.string.app_version);

    private static final int LOG_COUNT = 5;

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();
    private static final byte[] masterSecret = TicketActivity.outer.getString(R.string.master_secret).getBytes();

    /** TODO: Change these according to your design. Diversify the keys. */
    private static final byte[] authenticationKey = defaultAuthenticationKey; // 16-byte key
    private static final byte[] hmacKey = defaultHMACKey; // 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private final Boolean isValid = false;
    private final int remainingUses = 0;
    private final int expiryTime = 0;
    private final String code = "moi dan";

    private static String infoToShow = "-"; // Use this to show messages

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        return infoToShow;
    }

    private static byte[] convertLongToByteArray(long nmb) {
        return ByteBuffer.allocate(8).putLong(nmb).array();
    }

    private static long convertByteArrayToLong(byte[] array) {
        return ByteBuffer.wrap(array).getLong();
    }

    private static byte[] convertIntToByteArray(int nmb) {
        return ByteBuffer.allocate(4).putInt(nmb).array();
    }

    private static int convertByteArrayToInt(byte[] array) {
        return ByteBuffer.wrap(array).getInt();
    }

    private static short readCounterFromCard() {
        // Example of reading:
        byte[] message = new byte[2];
        boolean res = utils.readPage(41, message);

        if (res) {
            short number = (short) (message[0] + (message[1] << 8));
            return number;
        }

        return 0;
    }

    private static void writeLog(LogType type, byte[] payload) {
        if (payload.length > 4) throw new IllegalArgumentException("Payload cannot be longer than 4 bytes!");

        byte[] nextLogPageNumberBytes = new byte[4];
        utils.readPage(39, nextLogPageNumberBytes);
        int nextLogPageNumber = convertByteArrayToInt(nextLogPageNumberBytes);

        if (nextLogPageNumber > 38 || nextLogPageNumber < 38 - LOG_COUNT * 3) {
            nextLogPageNumber = 38;
        }

        utils.writePage(type.getId().getBytes(), nextLogPageNumber);
        utils.writePage(payload, nextLogPageNumber - 1);

        int currentTimeInSeconds = (int) System.currentTimeMillis() / 1000 / 60;
        utils.writePage(convertIntToByteArray(currentTimeInSeconds), nextLogPageNumber - 2);

        nextLogPageNumberBytes = convertIntToByteArray(nextLogPageNumber - 3);
        utils.writePage(nextLogPageNumberBytes, 39);
    }

    private static byte[] calculateMacBytes(byte[] appIdBytes, byte[] appVersionBytes, byte[] counterLimitBytes,
                                            byte[] expirationBytes, byte[] uuidBytes) throws GeneralSecurityException {
        if (appIdBytes.length != 4) throw new IllegalArgumentException("appIdBytes array needs to have a length of 4");
        if (appVersionBytes.length != 4) throw new IllegalArgumentException("appVersionBytes array needs to have a length of 4");
        if (counterLimitBytes.length != 4) throw new IllegalArgumentException("counterLimitBytes array needs to have a length of 4");
        if (expirationBytes.length != 4) throw new IllegalArgumentException("expirationBytes array needs to have a length of 4");
        if (uuidBytes.length != 4) throw new IllegalArgumentException("uuidBytes array needs to have a length of 4");

        byte[] macInput = new byte[4 + 4 + 4 + 4 + 4];
        System.arraycopy(appIdBytes, 0, macInput, 0, 4);
        System.arraycopy(appVersionBytes, 0, macInput, 4, 4);
        System.arraycopy(counterLimitBytes, 0, macInput, 8, 4);
        System.arraycopy(expirationBytes, 0, macInput, 12, 4);
        System.arraycopy(uuidBytes, 0, macInput, 16, 4);
        macAlgorithm.setKey(macInput);

        byte[] macBytes = new byte[4];
        macAlgorithm.generateMac(macBytes);

        return macBytes;
    }

    private static byte[] generatePrivateKeyFromUid(byte[] uidBytes) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec hmacKey = new SecretKeySpec(masterSecret, "HmacSHA256");
            mac.init(hmacKey);

            return mac.doFinal(uidBytes);
        } catch (NoSuchAlgorithmException e) {
            // there will be such algorithm though
            Utilities.log("No such algorithm as SHA256...", true);
        } catch (InvalidKeyException e) {
            Utilities.log("Invalid master key for SHA256...", true);
        }

        return new byte[0];
    }

    private static short initializeCounterIfNeeded() {
        short currentCounter = readCounterFromCard();
        if (currentCounter == 0) {
            // try writing to the counter, since it might not have been written to
            byte[] littleEndian = new byte[2];
            littleEndian[0] = (byte) 1;

            if (utils.writePage(littleEndian, 41)) {
                currentCounter = 1;
            } else {
                return -1;
            }
        }

        return currentCounter;
    }

    private static byte[] writeUidToCard(int page) {
        // writing uid of card
        SecureRandom random = new SecureRandom();
        byte[] uuidBytes = new byte[4];
        random.nextBytes(uuidBytes);
        utils.writePage(uuidBytes, page);

        return uuidBytes;
    }

    private static byte[] writeAppId(int page) {
        byte[] appIdBytes = APP_ID.getBytes();
        utils.writePage(APP_ID.getBytes(), 4);

        return appIdBytes;
    }

    private static byte[] writeAppVersion(int page) {
        byte[] appVersionBytes = APP_VERSION.getBytes();
        utils.writePage(APP_VERSION.getBytes(), 5);

        return appVersionBytes;
    }

    private static byte[] writeCounterLimit(short currentCounter, int uses, int page) {
        byte[] counterLimitBytes = convertIntToByteArray(currentCounter + uses);

        // writing current counter to data
        utils.writePage(counterLimitBytes, page);

        return counterLimitBytes;
    }

    private static byte[] writeExpirationDate(int daysValid, int page) {
        long currentMinutes = System.currentTimeMillis() / 1000 / 60;
        int expirationDate = (int) currentMinutes + daysValid * 24 * 60;
        byte[] expirationBytes = convertIntToByteArray(expirationDate);
        utils.writePage(expirationBytes,page);

        return expirationBytes;
    }


    private static final int PAGE_UID = 4;
    private static final int PAGE_APP_ID = 5;
    private static final int PAGE_APP_VERSION = 6;
    private static final int PAGE_COUNTER_LIMIT = 7;
    private static final int PAGE_EXPIRATION_DATE = 8;
    private static final int PAGE_MAC = 9;

    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        // Authenticate
        boolean res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";

            writeLog(LogType.ISSUE, new byte[] { 1, 0, 0, 0 });
            return false;
        }

        // counter of card
        short currentCounter = initializeCounterIfNeeded();
        if (currentCounter == -1) {
            Utilities.log("Couldn't read counter issue()", true);
            infoToShow = "Couldn't read counter";

            writeLog(LogType.ISSUE, new byte[] { 0, 1, 0, 0 });
        }

        // page 4: uuid
        byte[] uuidBytes = writeUidToCard(PAGE_UID);

        // private key
        byte[] privateKey = generatePrivateKeyFromUid(uuidBytes);
        utils.writePages(privateKey, 0, 44, 4);

        // page 5: app id
        byte[] appIdBytes = writeAppId(PAGE_APP_ID);

        // page 6: app version
        byte[] appVersionBytes = writeAppVersion(PAGE_APP_VERSION);

        // page 7: counter limit
        byte[] counterLimitBytes = writeCounterLimit(currentCounter, uses, PAGE_COUNTER_LIMIT);

        // page 8: expiration day
        byte[] expirationBytes = writeExpirationDate(daysValid, PAGE_EXPIRATION_DATE);

        // page 9: mac
        // generate hmac from static data
        byte[] macBytes = calculateMacBytes(appIdBytes, appVersionBytes, counterLimitBytes,
                                            expirationBytes, uuidBytes);
        utils.writePage(macBytes, PAGE_MAC);

        infoToShow = "Successful!";

        writeLog(LogType.ISSUE, new byte[] { 0, 0, 0, 0 });

        return true;
    }

    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        byte[] uuidBytes = new byte[4];
        utils.readPage(PAGE_UID, uuidBytes);

        byte[] privateKey = generatePrivateKeyFromUid(uuidBytes);

        // Authenticate
        boolean res = utils.authenticate(privateKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";

            writeLog(LogType.RIDE_USE, new byte[] { 1, 0, 0, 0 });
            return false;
        }

        // check app id
        byte[] appIdBytes = new byte[4];
        utils.readPage(PAGE_APP_ID, appIdBytes);

        if (!new String(appIdBytes).equals(APP_ID)) {
            Utilities.log("Invalid app ID", true);
            infoToShow = "Invalid app ID";

            writeLog(LogType.RIDE_USE, new byte[] { 0, 1, 0, 0 });
            return false;
        }

        // check app version
        byte[] versionBytes = new byte[4];
        utils.readPage(PAGE_APP_VERSION, versionBytes);

        if (!new String(versionBytes).equals(APP_VERSION)) {
            Utilities.log("Invalid app version", true);
            infoToShow = "Invalid app version";

            writeLog(LogType.RIDE_USE, new byte[] { 0, 2, 0, 0 });
            return false;
        }

        byte[] expirationBytes = new byte[8];
        utils.readPage(PAGE_EXPIRATION_DATE, expirationBytes);

        long expiration = convertByteArrayToLong(expirationBytes);
        long currentTimeInMinutes = System.currentTimeMillis() / 1000 / 60;
        if (currentTimeInMinutes > expiration) {
            Utilities.log("Expired card!", false);
            infoToShow = "Expired card!";

            writeLog(LogType.RIDE_USE, new byte[] { 0, 0, 1, 0 });
            return false;
        }

        byte[] counterLimitBytes = new byte[4];
        utils.readPage(PAGE_COUNTER_LIMIT, counterLimitBytes);
        int counterLimit = convertByteArrayToInt(counterLimitBytes);
        int currentCounter = readCounterFromCard();

        if (currentCounter >= counterLimit) {
            Utilities.log("No more rides!", false);
            infoToShow = "No more rides!";

            writeLog(LogType.RIDE_USE, new byte[] { 0, 0, 2, 0 });
            return false;
        }

        byte[] calculatedMacBytes = calculateMacBytes(appIdBytes, versionBytes, counterLimitBytes,
                                                       expirationBytes, uuidBytes);
        byte[] readMacBytes = new byte[4];
        utils.readPage(PAGE_MAC, readMacBytes);
        for (int i = 0; i < calculatedMacBytes.length; i++) {
            if (calculatedMacBytes[i] != readMacBytes[i]) {
                Utilities.log("Invalid MAC in issue()", true);
                infoToShow = "Invalid MAC";

                writeLog(LogType.RIDE_USE, new byte[] { 2, 0, 0, 0 });
                return false;
            }
        }

        // increment counter
        byte[] littleEndian = new byte[2];
        littleEndian[0] = (byte) 1;

        if (utils.writePage(littleEndian, 41)) {
            infoToShow = "Have fun! :^) 🎢 \nTickets left: " + (counterLimit - currentCounter - 1);

            writeLog(LogType.RIDE_USE, new byte[] { 0, 0, 0, 0 });
        } else {
            infoToShow = "Error while increasing counter!";

            writeLog(LogType.RIDE_USE, new byte[] { 0, 0, 0, 1 });
        }


        return true;
    }
}