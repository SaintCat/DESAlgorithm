/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package des;

/**
 *
 * @author Роман
 */
public class ByteUtils {

    public static byte[] selectBits(byte[] in, int[] map) {
        int numOfBytes = (map.length - 1) / 8 + 1;
        byte[] out = new byte[numOfBytes];
        for (int i = 0; i < map.length; i++) {
            int val = getBit(in, map[i] - 1);
            setBit(out, i, val);
        }
        return out;
    }

    public static byte[] selectBits(byte[] in, int pos, int len) {
        int numOfBytes = (len - 1) / 8 + 1;
        byte[] out = new byte[numOfBytes];
        for (int i = 0; i < len; i++) {
            int val = getBit(in, pos + i);
            setBit(out, i, val);
        }
        return out;
    }

    public static byte[] concatenateBits(byte[] a, int aLen, byte[] b, int bLen) {
        int numOfBytes = (aLen + bLen - 1) / 8 + 1;
        byte[] out = new byte[numOfBytes];
        int j = 0;
        for (int i = 0; i < aLen; i++) {
            int val = getBit(a, i);
            setBit(out, j, val);
            j++;
        }
        for (int i = 0; i < bLen; i++) {
            int val = getBit(b, i);
            setBit(out, j, val);
            j++;
        }
        return out;
    }

    public static byte[] rotateLeft(byte[] in, int len, int step) {
        int numOfBytes = (len - 1) / 8 + 1;
        byte[] out = new byte[numOfBytes];
        for (int i = 0; i < len; i++) {
            int val = getBit(in, (i + step) % len);
            setBit(out, i, val);
        }
        return out;
    }

    public static byte[] doXORBytes(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    public static byte[] splitBytes(byte[] in, int len) {
        int numOfBytes = (8 * in.length - 1) / len + 1;
        byte[] out = new byte[numOfBytes];
        for (int i = 0; i < numOfBytes; i++) {
            for (int j = 0; j < len; j++) {
                int val = getBit(in, len * i + j);
                setBit(out, 8 * i + j, val);
            }
        }
        return out;
    }

    private static int getBit(byte[] data, int pos) {
        int posByte = pos / 8;
        int posBit = pos % 8;
        byte valByte = data[posByte];
        int valInt = valByte >> (8 - (posBit + 1)) & 1;
        return valInt;
    }

    private static void setBit(byte[] data, int pos, int val) {
        int posByte = pos / 8;
        int posBit = pos % 8;
        byte oldByte = data[posByte];
        if (val == 1) {
            oldByte = (byte) (oldByte | (1 << (8 - (posBit + 1))));
        } else {
            oldByte = (byte) (oldByte & ~(1 << (8 - (posBit + 1))));
        }
        data[posByte] = oldByte;
    }
}
