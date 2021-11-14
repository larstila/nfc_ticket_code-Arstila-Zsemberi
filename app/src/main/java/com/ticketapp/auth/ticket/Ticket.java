package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Date;

/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You
 * will need to change the keys, design and implement functions to issue and validate tickets. Keep
 * you code readable and write clarifying comments when necessary.
 */
public class Ticket {
    private static final String APP_ID = TicketActivity.outer.getString(R.string.app_id);
    private static final String APP_VERSION = TicketActivity.outer.getString(R.string.app_version);


    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();

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

    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        // Authenticate
        boolean res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        short currentCounter = readCounterFromCard();
        if (currentCounter == 0) {
            // try writing to the counter, since it might not have been written to
            byte[] littleEndian = new byte[2];
            littleEndian[0] = (byte) 1;

            if (utils.writePage(littleEndian, 41)) {
                infoToShow = "Counter initialized to 1";
                currentCounter = 1;
            } else {
                Utilities.log("Couldn't read counter issue()", true);
                infoToShow = "Couldn't read counter";
                return false;
            }
        }
        // TODO: validation
        utils.writePage(APP_ID.getBytes(), 4);
        utils.writePage(APP_VERSION.getBytes(), 5);

        // writing current counter to data
        utils.writePage(convertIntToByteArray(currentCounter + uses), 6);

        long currentMinutes = System.currentTimeMillis() / 1000 / 60;
        long expirationDate = currentMinutes + daysValid * 24 * 60;

        utils.writePages(convertLongToByteArray(expirationDate), 0, 7, 2);
        infoToShow = "Successful!";

        return true;
    }

    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        // Authenticate
        res = utils.authenticate(authenticationKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        byte[] appIdBytes = new byte[4];
        byte[] versionBytes = new byte[4];
        utils.readPage(4, appIdBytes);
        utils.readPage(5, versionBytes);

        if (!new String(appIdBytes).equals(APP_ID)) {
            Utilities.log("Invalid app ID", true);
            infoToShow = "Invalid app ID";
            return false;
        }

        if (!new String(versionBytes).equals(APP_VERSION)) {
            Utilities.log("Invalid app version", true);
            infoToShow = "Invalid app version";
            return false;
        }

        byte[] expirationBytes = new byte[8];
        utils.readPages(7, 2, expirationBytes, 0);

        long expiration = convertByteArrayToLong(expirationBytes);
        long currentTimeInMinutes = System.currentTimeMillis() / 1000 / 60;
        if (currentTimeInMinutes > expiration) {
            Utilities.log("Expired card!", false);
            infoToShow = "Expired card!";
            return false;
        }

        byte[] counterLimitBytes = new byte[4];
        utils.readPage(6, counterLimitBytes);
        int counterLimit = convertByteArrayToInt(counterLimitBytes);
        int currentCounter = readCounterFromCard();

        if (currentCounter >= counterLimit) {
            Utilities.log("No more rides!", false);
            infoToShow = "No more rides!";
            return false;
        }

        // increment counter
        byte[] littleEndian = new byte[2];
        littleEndian[0] = (byte) 1;

        if (utils.writePage(littleEndian, 41)) {
            infoToShow = "Have fun! :^) 🎢 \nTickets left: " + (counterLimit - currentCounter - 1);
        } else {
            infoToShow = "Error while increasing counter!";
        }


        return true;
    }
}