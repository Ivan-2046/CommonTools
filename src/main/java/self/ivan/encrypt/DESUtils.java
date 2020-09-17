package self.ivan.encrypt;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class DESUtils {

    private static final byte[] KEY_IV = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};

    private static final String CHARSET = "UTF-8";

    public static String encodeByECB(String encryptKey, String text) throws Exception {
        byte[] key = new BASE64Decoder().decodeBuffer(encryptKey);
        byte[] data = text.getBytes(CHARSET);
        byte[] encodeByte = des3EncodeECB(key, data);
        return new BASE64Encoder().encode(encodeByte);
    }

    public static String encodeByCBC(String encryptKey, String text) throws Exception {
        byte[] key = new BASE64Decoder().decodeBuffer(encryptKey);
        byte[] data = text.getBytes(CHARSET);
        byte[] encodeByte = des3EncodeCBC(key, KEY_IV, data);
        String encode = new BASE64Encoder().encode(encodeByte);
        return new BASE64Encoder().encode(encode.getBytes(CHARSET));
    }

    public static String decodeByECB(String encryptKey, String encodeData) throws Exception {
        byte[] key = new BASE64Decoder().decodeBuffer(encryptKey);
        byte[] decodeStr = des3DecodeECB(key, new BASE64Decoder().decodeBuffer(encodeData));
        return new String(decodeStr, CHARSET);
    }

    public static String decodeByCBC(String encryptKey, String encodeData) throws Exception {
        String enc = new String(Base64.decode(encodeData), StandardCharsets.UTF_8);
        byte[] key = new BASE64Decoder().decodeBuffer(encryptKey);
        byte[] decodeStr = des3DecodeCBC(key, KEY_IV, new BASE64Decoder().decodeBuffer(enc));
        return new String(decodeStr, CHARSET);
    }

    /**
     * ECB加密,不要IV
     *
     * @param key  密钥
     * @param data 明文
     * @return Base64编码的密文
     * @throws Exception
     */
    private static byte[] des3EncodeECB(byte[] key, byte[] data) throws Exception {
        DESedeKeySpec spec = new DESedeKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("desede");
        Key desKey = keyFactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("desede" + "/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, desKey);
        return cipher.doFinal(data);
    }

    /**
     * ECB解密,不要IV
     *
     * @param key  密钥
     * @param data Base64编码的密文
     * @return 明文
     */
    private static byte[] des3DecodeECB(byte[] key, byte[] data) throws Exception {
        DESedeKeySpec spec = new DESedeKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("desede");
        Key desKey = keyFactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("desede" + "/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, desKey);
        return cipher.doFinal(data);
    }

    /**
     * CBC加密
     *
     * @param key   密钥
     * @param keyIv IV
     * @param data  明文
     * @return Base64编码的密文
     */
    private static byte[] des3EncodeCBC(byte[] key, byte[] keyIv, byte[] data) throws Exception {
        DESedeKeySpec spec = new DESedeKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("desede");
        Key desKey = keyFactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("desede" + "/CBC/PKCS5Padding");
        IvParameterSpec ips = new IvParameterSpec(keyIv);
        cipher.init(Cipher.ENCRYPT_MODE, desKey, ips);
        return cipher.doFinal(data);
    }

    /**
     * CBC解密
     *
     * @param key   密钥
     * @param keyiv IV
     * @param data  Base64编码的密文
     * @return 明文
     * @throws Exception
     */
    private static byte[] des3DecodeCBC(byte[] key, byte[] keyiv, byte[] data) throws Exception {
        DESedeKeySpec spec = new DESedeKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("desede");
        Key desKey = keyFactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("desede" + "/CBC/PKCS5Padding");
        IvParameterSpec ips = new IvParameterSpec(keyiv);
        cipher.init(Cipher.DECRYPT_MODE, desKey, ips);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        String text = "hello des";
        String encryptKey = "E45754DDCAAC4C8F8490F6D724599977";
        String encrypt = encodeByCBC(encryptKey, text);
        System.out.println("cbc encode >>> " + encrypt);

        String cbcdecoder = decodeByCBC(encryptKey, encrypt);
        System.out.println("decoder >>> " + cbcdecoder);


        encrypt = encodeByECB(encryptKey, text);
        System.out.println("ecb encode >>> " + encrypt);

        cbcdecoder = decodeByECB(encryptKey, encrypt);
        System.out.println("ecb >>> " + cbcdecoder);
    }
}
