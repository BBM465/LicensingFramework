import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class LicenceManager {
    private byte[] encryptedLicenseContent;
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
    public void setEncryptedLicenseContent(byte[] encryptedLicenseContent) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException, SignatureException {
        System.out.println("Server -- Server is being requested... ");
        this.encryptedLicenseContent = encryptedLicenseContent;
        System.out.print("Server -- Incoming Encrypted Text: ");
        System.out.println(new String(Base64.getUrlEncoder().encode(encryptedLicenseContent)));
        //first element in list encrypted text,second element is encrypted key
        sendSignature();
    }

    private byte[] DecryptLicenseContent() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // decrypt the content with the private key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(encryptedLicenseContent);
        String decryptedText =  new String(decrypted);
        System.out.println("Server -- Decrypted Text: " + decryptedText);
        return decrypted;
    }

    private byte[] HashDecryptedLicenseContent() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        MessageDigest digest = MessageDigest.getInstance("MD5"); // take the hash of the decrypted license content with MD5
        byte[] hash = digest.digest(DecryptLicenseContent());
        String hashedLicense = new String(Base64.getUrlEncoder().encode(hash), StandardCharsets.UTF_8);
        System.out.println("Server -- MD5 Plain License Text: " + hashedLicense);
        return hash;
    }

    private byte[] SignHashedLicenseContent() throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(privateKey); // sign the message with private key
        signature.update(HashDecryptedLicenseContent()); // sign hash of the decrypted message
        byte[] signed = signature.sign();
        System.out.println("Server -- Digital Signature: " + new String(Base64.getUrlEncoder().encode(signed)));
        return signed;
    }

    public void sendSignature() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, SignatureException, InvalidKeyException {
        setSignature(SignHashedLicenseContent());
    }
}