package ms.safi.rsa.securid;

import ms.safi.rsa.model.Token;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;

public class Generator {
    private static final int FLD_DIGIT_SHIFT = 6;
    private static final int FLD_DIGIT_MASK = (0x07 << FLD_DIGIT_SHIFT);

    public static ZonedDateTime currentTime() {
        return Instant.now().atZone(ZoneId.of("UTC"));
    }

    // CONVERTED C FUNCTIONS BELOW

    public static String securid_compute_tokencode(Token token, ZonedDateTime time) {
        boolean is_30 = token.getInterval() == 30;

        int[] bcd_time = new int[8];
        bcd_write(bcd_time, time.getYear(), 0, 2);
        bcd_write(bcd_time, time.getMonth().getValue(), 2, 1);
        bcd_write(bcd_time, time.getDayOfMonth(), 3, 1);
        bcd_write(bcd_time, time.getHour(), 4, 1);
        bcd_write(bcd_time, time.getMinute() & ~(is_30 ? 0x01 : 0x3), 5, 1);
        bcd_time[6] = bcd_time[7] = 0;

        int[] key0 = new int[16];
        int[] key1 = new int[16];

        key0 = key_from_time(bcd_time, 2, token.getSerial(), key0);
        key0 = AES128_ECB_encrypt(key0, token.getSeed());

        key1 = key_from_time(bcd_time, 3, token.getSerial(), key1);
        key1 = AES128_ECB_encrypt(key1, key0);

        key0 = key_from_time(bcd_time, 4, token.getSerial(), key0);
        key0 = AES128_ECB_encrypt(key0, key1);

        key1 = key_from_time(bcd_time, 5, token.getSerial(), key1);
        key1 = AES128_ECB_encrypt(key1, key0);

        key0 = key_from_time(bcd_time, 8, token.getSerial(), key0);
        key0 = AES128_ECB_encrypt(key0, key1);

        /* key0 now contains 4 consecutive token codes */
        int i;
        if (is_30) {
            i = ((time.getMinute() & 0x01) << 3) | (((time.getSecond() >= 30) ? 1 : 0) << 2);
        } else {
            i = (time.getMinute() & 0x03) << 2;
        }

        long t1 = ((long) (key0[i + 0]) & 0xFF) << 24;
        long t2 = ((long) (key0[i + 1]) & 0xFF) << 16;
        long t3 = ((long) (key0[i + 2]) & 0xFF) << 8;
        long t4 = ((long) (key0[i + 3]) & 0xFF) << 0;

        long tokencode = t1 | t2 | t3 | t4;

        /* populate code_out backwards, adding PIN digits if available */
        char[] out = new char[16];
        int j = ((token.getFlags() & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) + 1;
        out[j--] = 0;
        for (i = 0; j >= 0; j--, i++) {
            int c = (int) (tokencode % 10);
            tokencode /= 10;

            if (i < token.getPin().length()) {
                c += token.getPin().charAt(token.getPin().length() - i - 1) - '0';
            }
            out[j] = (char) (c % 10 + '0');
        }

        return new String(out).trim();
    }

    private static void bcd_write(int[] out, int val, int offset, int bytes) {
        for (int i = bytes - 1; i >= 0; i--) {
            out[i + offset] = val % 10;
            val /= 10;
            out[i + offset] |= (val % 10) << 4;
            val /= 10;
        }
    }

    private static int[] key_from_time(int[] bcd_time, int bcd_time_bytes, String serial, int[] key) {
        Arrays.fill(key, 0, 8, 0xaa);
        Arrays.fill(key, 12, key.length, 0xbb);
        System.arraycopy(bcd_time, 0, key, 0, bcd_time_bytes);

        int k = 8;
        for (int i = 4; i < 12; i += 2) {
            key[k++] = ((serial.charAt(i) - '0') << 4) | (serial.charAt(i + 1) - '0');
        }

        return key;
    }

    private static byte[] intToByteArray(int[] input) {
        byte[] bytes = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            bytes[i] = (byte) input[i];
        }
        return bytes;
    }

    private static int[] byteToIntArray(byte[] input) {
        int[] ints = new int[input.length];
        for (int i = 0; i < input.length; i++) {
            ints[i] = (int) input[i];
        }
        return ints;
    }

    private static int[] AES128_ECB_encrypt(int[] input, int[] key) {
        byte[] keyByte = intToByteArray(key);
        byte[] inputByte = intToByteArray(input);

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec secretKey = new SecretKeySpec(keyByte, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return byteToIntArray(cipher.doFinal(inputByte));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
