package com.ticketapp.auth.app.ulctools;

/**
 * Developed for Aalto University course CS-E4300 Network Security.
 * Copyright (C) 2021-2022 Aalto University
 */
public class Commands {

    public boolean readBinary(int adr, byte[] dstBuffer, int dstPos) {
        byte[] data = Reader.readPage(adr, false);
        if (data.length > 0) {
            System.arraycopy(data, 0, dstBuffer, dstPos, Math.min(4, dstBuffer.length));
        } else return false;
        return true;
    }

    /**
     * Write a byte array on the card to the one defined page.
     *
     * @param adr       destination page
     * @param srcBuffer byte array to be stored on the card
     * @param srcPos    starting position of the data to write on input array
     * @return boolean value of success
     */
    public boolean writeBinary(int adr, byte[] srcBuffer, int srcPos) {
        byte[] data = new byte[4];
        System.arraycopy(srcBuffer, srcPos, data, 0, Math.min(4, srcBuffer.length));
        return Reader.updatePage(data, adr, false);
    }

    /**
     * Write a byte array on the card to the one defined page.
     *
     * @param adr       destination page
     * @param srcBuffer byte array to be stored on the card
     * @return boolean value of success
     */
    public boolean writeBinaryWhole(int adr, byte[] srcBuffer) {
        byte[] data = new byte[srcBuffer.length];
        System.arraycopy(srcBuffer, 0, data, 0, srcBuffer.length);
        return Reader.updatePage(data, adr, false);
    }
}
