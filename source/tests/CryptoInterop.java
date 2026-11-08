import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;

public final class CryptoInterop {
    private static final byte[] AAD = "LATCHKEY/1".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        byte[] key = Base64.getUrlDecoder().decode(args[1]);
        if ("decrypt".equals(mode)) {
            byte[] blob = Files.readAllBytes(Paths.get(args[2]));
            byte[] nonce = Arrays.copyOfRange(blob, 0, 12);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            cipher.updateAAD(AAD);
            byte[] plaintext = cipher.doFinal(blob, 12, blob.length - 12);
            Files.write(Paths.get(args[3]), plaintext);
        } else if ("encrypt".equals(mode)) {
            byte[] plaintext = Files.readAllBytes(Paths.get(args[2]));
            byte[] nonce = new byte[12];
            for (int i = 0; i < nonce.length; i++) {
                nonce[i] = (byte) i;
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            cipher.updateAAD(AAD);
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] out = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(ciphertext, 0, out, nonce.length, ciphertext.length);
            Files.write(Paths.get(args[3]), out);
        } else {
            throw new IllegalArgumentException("mode must be encrypt or decrypt");
        }
    }
}
