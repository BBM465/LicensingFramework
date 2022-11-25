import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class LicenceManager {
    private String encryptedLicenseContent;
    private final PrivateKey privateKey;

    public LicenceManager() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("src/keys/private.key"))));
    }
    public void setEncryptedLicenseContent(String encryptedLicenseContent) {
        this.encryptedLicenseContent = encryptedLicenseContent;
    }

    private String DecryptLicenseContent() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // decrypt the content with the private key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(encryptedLicenseContent.getBytes()));
    }

    private String HashDecryptedLicenseContent() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        MessageDigest digest = MessageDigest.getInstance("MD5"); // take the hash of the decrypted license content with MD5
        byte[] hash = digest.digest(DecryptLicenseContent().getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(hash), StandardCharsets.UTF_8); // convert the hashed bytes to string
    }

    // https://stackoverflow.com/questions/7224626/how-to-sign-string-with-private-key
    private String SignHashedLicenseContent() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(privateKey); // sign the message with private key
        signature.update(HashDecryptedLicenseContent().getBytes()); // sign hash of the decrypted message
        return new String(Base64.getEncoder().encode(signature.sign()));
    }

    public void sendSignature(Client client) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, SignatureException, InvalidKeyException {
        client.setSignature(SignHashedLicenseContent().getBytes());
    }
}
