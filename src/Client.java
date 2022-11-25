import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Client {
    private final String serialNumber;
    private final String username;
    private final String motherboardSerialNumber;
    private String MACAddress;
    private final String diskSerialNumber;
    private byte[] signature;
    private final PublicKey publicKey;


    public Client(String motherboardSerialNumber, String diskSerialNumber) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        this.motherboardSerialNumber = motherboardSerialNumber; // os dependent - must be implemented hard-coded
        this.diskSerialNumber = diskSerialNumber; // os dependent - must be implemented hard-coded
        this.username = "ImreAndCagla"; // static
        this.serialNumber = "1234-5678-9012"; // static
        this.MACAddress = getMACAddress(); // the function to receive mac address can be implemented independent of the platform
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.publicKey = kf.generatePublic(new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of("src/keys/public.key"))));
    }
    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    private String getMACAddress() throws SocketException, UnknownHostException {
        InetAddress localHost = InetAddress.getLocalHost(); // get address for machine's local host
        NetworkInterface ni = NetworkInterface.getByInetAddress(localHost);
        byte[] hardwareAddress = ni.getHardwareAddress();
        String[] hexadecimal = new String[hardwareAddress.length];
        for (int i = 0; i < hardwareAddress.length; i++) { // return the address in hexadecimal format
            hexadecimal[i] = String.format("%02X", hardwareAddress[i]);
        }
        this.MACAddress = String.join(":", hexadecimal); // split each number with ":" character
        return MACAddress;
    }

    private String getLicenceContent(){
        return username + "$" + serialNumber + "$" + MACAddress + "$" + diskSerialNumber + "$" + motherboardSerialNumber;
    }

    private String EncryptLicenseContent() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // encrypt the content with public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return new String(cipher.doFinal(getLicenceContent().getBytes()));
    }

    public void sendEncryptedLicenseContent(LicenceManager licenceManager) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException {
        licenceManager.setEncryptedLicenseContent(EncryptLicenseContent());
    }

    private String HashLicenseContent() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5"); // take the hash of the license content with MD5
        byte[] hash = digest.digest(getLicenceContent().getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(hash), StandardCharsets.UTF_8); // convert the hashed bytes to string
    }

    // https://stackoverflow.com/questions/7224626/how-to-sign-string-with-private-key
    public boolean verifyLicense() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(publicKey); // verify signature with public key
        signature.update(HashLicenseContent().getBytes());
        return signature.verify(this.signature);
    }
}
