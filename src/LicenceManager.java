import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

public class LicenceManager {
    private List<byte[]> encryptedLicenseContent;
    private final PrivateKey privateKey;

    private byte[] signature;

    public void setSignature(byte[] signature){
        this.signature=signature;
    }

    public byte[] getSignature() {
        return signature;
    }

    public LicenceManager() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("src/keys/private.key"))));

    }
    public void setEncryptedLicenseContent(List<byte[]> encryptedLicenseContent) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException, SignatureException {
        this.encryptedLicenseContent = encryptedLicenseContent;
        //first element in list encrypted text,second element is encrypted key
        sendSignature();
    }

    private String DecryptLicenseContent() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //first element in the list is encrypted text,second element is encrypted key
        // decrypt the symmetric key  with the private key(RSA)
        byte[] encryptedKey = encryptedLicenseContent.get(1);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.PRIVATE_KEY, privateKey);
        byte[] symmetricKeyBytes = cipher.doFinal(encryptedKey);//burda diyoki bad padding
        //decrypt content with symmetric key
        SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes , 0, symmetricKeyBytes .length, "AES");
        Cipher cipher2 = Cipher.getInstance("AES");
        cipher2.init(Cipher.DECRYPT_MODE, symmetricKey);
        byte[] encryptedContent = encryptedLicenseContent.get(0);
        String content = new String( Base64.getDecoder().decode(cipher2.doFinal(encryptedContent)));
        return content;
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

    public void sendSignature() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, SignatureException, InvalidKeyException {
        setSignature(SignHashedLicenseContent().getBytes());
    }
}
