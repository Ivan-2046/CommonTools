package self.ivan.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class MD5Utils {

    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    public static String text2Md5(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] bytes = md.digest(text.getBytes(StandardCharsets.UTF_8));
            return toHex(bytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder ret = new StringBuilder(bytes.length * 2);
        for (byte bt : bytes) {
            ret.append(HEX_DIGITS[(bt >> 4) & 0x0f]);
            ret.append(HEX_DIGITS[bt & 0x0f]);
        }
        return ret.toString();
    }

}
