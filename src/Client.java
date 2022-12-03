import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class Client {
    private static String serialNumber;
    private static String username;
    private static String motherboardSerialNumber;
    private static String MACAddress;
    private static String diskSerialNumber;
    private byte[] signature;
    private static PublicKey publicKey;
    private static String licenseContent;
    private static String hashLicenseContent;
    public static LicenceManager licenceManager;
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException {
        System.out.println("Client started...");
        // change the address to function call when submitting
        MACAddress = "36:7d:da:df:54:9e"; // the function to receive mac address can be implemented independent of the platform
        System.out.println("My MAC: " + MACAddress);
        diskSerialNumber = "C02DW0N0ML7H"; // change it to windows function call when submitting
        System.out.println("My Disk ID: " + diskSerialNumber);
        // 4810-E58D for Windows Machine
        // C02DW0N0ML7H for macOS Machine
        motherboardSerialNumber = "820-01949-A"; // hard-coded for macOS machine - change it to windows function call when submitting
        System.out.println("My Motherboard ID: " + motherboardSerialNumber);
        System.out.println("LicenseManager service started...");
        username = "ImreAndCagla"; // static
        serialNumber = "1234-5678-9012"; // static
        KeyFactory kf = KeyFactory.getInstance("RSA");
        publicKey = kf.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(Path.of("src/keys/public.key"))));
        File f = new File("licence.txt");
        licenceManager=new LicenceManager();
        if(f.exists() && !f.isDirectory()) {

        }else {
            System.out.println("Client -- License file is not found.");
            getLicenceContent();
            sendEncryptedLicenseContent(licenceManager);
            byte[] managersLicence = licenceManager.getSignature();
            if(verifyLicense(managersLicence)){
                System.out.println("Client -- License file is not found.");
                System.out.println("Client -- Succeeded. The license file content is secured and signed by the server.");
            }
        }
    }
    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    private static String getMACAddress() throws SocketException, UnknownHostException {
        InetAddress localHost = InetAddress.getLocalHost();
        NetworkInterface ni = NetworkInterface.getByInetAddress(localHost);
        byte[] hardwareAddress = ni.getHardwareAddress();
        String[] hexadecimal = new String[hardwareAddress.length];
        for (int i = 0; i < hardwareAddress.length; i++) { // return the address in hexadecimal format
            hexadecimal[i] = String.format("%02X", hardwareAddress[i]);
        }
        MACAddress = String.join(":", hexadecimal); // split each number with ":" character
        return MACAddress;
    }

    private static String getLicenceContent(){
        String rawLicenseText = username + "$" + serialNumber + "$" + MACAddress + "$" + diskSerialNumber + "$" + motherboardSerialNumber;
        licenseContent = rawLicenseText;
        System.out.println("Client -- Raw License Text: " + rawLicenseText);
        return rawLicenseText;
    }

    private static byte[] EncryptLicenseContent() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // encrypt the content with public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(licenseContent.getBytes());
        System.out.print("Client -- Encrypted License Text: ");
        System.out.println(new String(Base64.getUrlEncoder().encode(encrypted)));
        return encrypted;
    }

    public static void sendEncryptedLicenseContent(LicenceManager licenceManager) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException, SignatureException {
        byte[] content = EncryptLicenseContent();
        HashLicenseContent();
        System.out.println("Server is being requested... ");
        licenceManager.setEncryptedLicenseContent(content);
    }

    private static String HashLicenseContent() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5"); // take the hash of the license content with MD5
        byte[] hash = digest.digest(licenseContent.getBytes(StandardCharsets.UTF_8));
        String md5LicenseText = new String(Base64.getUrlEncoder().encode(hash), StandardCharsets.UTF_8);
        System.out.println("Client -- MD5 License Text: " + md5LicenseText);
        hashLicenseContent = md5LicenseText;
        return md5LicenseText; // convert the hashed bytes to string
    }

    public static boolean verifyLicense(byte[] licenceSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(publicKey); // verify signature with public key
        signature.update(Base64.getUrlDecoder().decode(hashLicenseContent));
        return signature.verify(licenceSignature);
    }
}
