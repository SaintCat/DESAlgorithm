/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

import static des.ByteUtils.concatenateBits;
import static des.ByteUtils.doXORBytes;
import static des.ByteUtils.rotateLeft;
import static des.ByteUtils.selectBits;
import static des.ByteUtils.splitBytes;
import static des.DESMatrices.E;
import static des.DESMatrices.INVP;
import static des.DESMatrices.IP;
import static des.DESMatrices.P;
import static des.DESMatrices.PC1;
import static des.DESMatrices.PC2;
import static des.DESMatrices.S;
import static des.DESMatrices.SHIFTS;

/**
 *
 * @author Роман
 */
public class DESAlgorithm {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        byte[] theKey = "desalgorithmkey".getBytes();
        byte[][] subKeys = generateKeys(theKey);
        byte[] theMsg = "i want to encrypt this message1111111111".getBytes();
        byte[] theCph = crypto(theMsg, subKeys, EncryptType.ENCRYPT);
        byte[] theDecr = crypto(theCph, subKeys, EncryptType.DECRYPT);
        System.out.println("Key: \n" + new String(theKey));
        System.out.println("Open message: \n" + new String(theMsg));
        System.out.println("Ecrypted message: \n" + new String(theCph));
        System.out.println("Decrypted message: \n" + new String(theDecr));
    }
    
    public static byte[] crypto(byte[] originMessage, byte[][] subKeys, EncryptType type) {
        if (originMessage.length < 8) {
            throw new IllegalArgumentException("Message is less than 64 bits.");
        }
        byte[][] splittedMessage = splitMessageTo64bits(originMessage, 8);
        byte[] resultMessage = new byte[]{};
        for (int i = 0; i < splittedMessage.length; i++) {
            byte[] message = splittedMessage[i];
            message = selectBits(message, IP);
            int blockSize = IP.length;
            byte[] l = selectBits(message, 0, blockSize / 2);
            byte[] r = selectBits(message, blockSize / 2, blockSize / 2);
            int numOfSubKeys = subKeys.length;
            for (int k = 0; k < numOfSubKeys; k++) {
                byte[] rBackup = r;
                r = feistelFuction(r, type.equals(EncryptType.ENCRYPT) ? subKeys[k] : subKeys[numOfSubKeys - k - 1]);
                r = doXORBytes(l, r);
                l = rBackup;
            }
            byte[] lr = concatenateBits(r, blockSize / 2, l, blockSize / 2);
            lr = selectBits(lr, INVP);

            resultMessage = concatenateBits(resultMessage, resultMessage.length * 8, lr, blockSize);
        }

        return resultMessage;
    }

    private static byte[] feistelFuction(byte[] r, byte[] subKey) {
        r = selectBits(r, E);
        r = doXORBytes(r, subKey);
        r = substitution6x4(r);
        r = selectBits(r, P);
        return r;
    }

    private static byte[] substitution6x4(byte[] in) {
        in = splitBytes(in, 6);
        byte[] out = new byte[in.length / 2];
        int lhByte = 0;
        for (int b = 0; b < in.length; b++) {
            byte valByte = in[b];
            int r = 2 * (valByte >> 7 & 0x0001) + (valByte >> 2 & 0x0001); // 1 and 6
            int c = valByte >> 3 & 0x000F; // Middle 4 bits
            int hByte = S[64 * b + 16 * r + c]; // 4 bits (half byte) output
            if (b % 2 == 0) {
                lhByte = hByte; // Left half byte
            } else {
                out[b / 2] = (byte) (16 * lhByte + hByte);
            }
        }
        return out;
    }

    private static byte[][] splitMessageTo64bits(byte[] message, int splitSize) {
        int numOfSubMessages = message.length / splitSize;
        byte[][] splitted = new byte[numOfSubMessages][];
        for (int i = 0; i < numOfSubMessages; i++) {
            splitted[i] = new byte[splitSize];
            for (int k = 0; k < splitSize; k++) {
                splitted[i][k] = message[i * splitSize + k];
            }
        }
        return splitted;
    }

    public static byte[][] generateKeys(byte[] key) {
        int halfKeySize = PC1.length / 2;
        int numberOfKeys = SHIFTS.length;
        key = selectBits(key, PC1);
        byte[] c = selectBits(key, 0, halfKeySize);
        byte[] d = selectBits(key, halfKeySize, halfKeySize);
        byte[][] subKeys = new byte[numberOfKeys][];
        for (int k = 0; k < numberOfKeys; k++) {
            c = rotateLeft(c, halfKeySize, SHIFTS[k]);
            d = rotateLeft(d, halfKeySize, SHIFTS[k]);
            byte[] cd = concatenateBits(c, halfKeySize, d, halfKeySize);
            subKeys[k] = selectBits(cd, PC2);
        }
        return subKeys;
    }

    public static enum EncryptType {

        ENCRYPT,
        DECRYPT;
    }
}
