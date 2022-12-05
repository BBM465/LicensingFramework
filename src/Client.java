import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

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
        MACAddress = getMACAddress(); // the function to receive mac address can be implemented independent of the platform
        System.out.println("My MAC: " + MACAddress);
        diskSerialNumber = getSerialNumber();
        System.out.println("My Disk ID: " + diskSerialNumber);
        // 4810-E58D for Windows Machine
        // C02DW0N0ML7H for macOS Machine
        motherboardSerialNumber = getWindowsMotherBoardSerialNumber();
        System.out.println("My Motherboard ID: " + motherboardSerialNumber);
        System.out.println("LicenseManager service started...");
        username = "ImreAndCagla"; // static
        serialNumber = "1234-5678-9012"; // static
        KeyFactory kf = KeyFactory.getInstance("RSA");
        publicKey = kf.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(Path.of("public.key"))));
        getLicenceContent();
        HashLicenseContent();
        File f = new File("licence.txt");
        licenceManager=new LicenceManager();
        if(f.exists() && !f.isDirectory()) {

            try {
                byte[] licenceSignatureBytes= Files.readAllBytes(Path.of("licence.txt")); //If the signature corrupted,it may throw exception in here
                System.out.println("Client -- License file is found.");
                if(verifyLicense(licenceSignatureBytes)){
                    System.out.println("Client -- Succeed. The license is correct.");
                }else{
                    System.out.println("Client -- The license file has been broken!!");
                    Licencing(f);
                }
            }
            catch (Exception e){
                System.out.println("Client -- The license file has been broken!!");
                Licencing(f);
            }
        }else {
            System.out.println("Client -- License file is not found.");
            Licencing(f);
        }
    }

    public static void Licencing(File f) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, SignatureException, InvalidKeyException {
        System.out.println("Client -- Raw License Text: " + licenseContent);
        sendEncryptedLicenseContent(licenceManager);

        byte[] managersLicence = licenceManager.getSignature();
        if(verifyLicense(managersLicence)){
            System.out.println("Client -- License file is not found.");
            System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
            f.createNewFile();
            try (FileOutputStream outputStream = new FileOutputStream("licence.txt")) {
                outputStream.write(managersLicence);
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
        return rawLicenseText;
    }

    private static byte[] EncryptLicenseContent() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // encrypt the content with public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(licenseContent.getBytes());
        System.out.print("Client -- Encrypted License Text: ");
        System.out.println(new String(Base64.getUrlEncoder().encode(encrypted)));
        System.out.println("Client -- MD5 License Text: " + hashLicenseContent);
        return encrypted;
    }

    public static void sendEncryptedLicenseContent(LicenceManager licenceManager) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException, SignatureException {
        byte[] content = EncryptLicenseContent();
        licenceManager.setEncryptedLicenseContent(content);
    }

    private static String HashLicenseContent() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5"); // take the hash of the license content with MD5
        byte[] hash = digest.digest(licenseContent.getBytes(StandardCharsets.UTF_8));
        String md5LicenseText = new String(Base64.getUrlEncoder().encode(hash), StandardCharsets.UTF_8);
        hashLicenseContent = md5LicenseText;
        return md5LicenseText; // convert the hashed bytes to string
    }

    public static boolean verifyLicense(byte[] licenceSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(publicKey); // verify signature with public key
        try{
        signature.update(Base64.getUrlDecoder().decode(hashLicenseContent));
        }
        catch (Exception e){
            return false;
        }
        return signature.verify(licenceSignature);
    }

    public static String getWindowsMotherBoardSerialNumber()
    {
        String command = "wmic baseboard get serialnumber";
        String serial=null;

        try {
            Process SerialNumberProcess
                    = Runtime.getRuntime().exec(command);
            InputStreamReader ISR = new InputStreamReader(
                    SerialNumberProcess.getInputStream());
            BufferedReader br = new BufferedReader(ISR);
            for(int i=0;i<3;i++){
                serial = br.readLine().trim();
                SerialNumberProcess.waitFor();
            }
            br.close();
        }
        catch (Exception e) {
            e.printStackTrace();
            serial = null;
        }
        return serial;
    }

    public static String getSerialNumber() throws IOException {
        String line;
        String serial = null;
        String command = "wmic diskdrive get serialnumber";
        try {
            Process SerialNumberProcess
                    = Runtime.getRuntime().exec(command);
            InputStreamReader ISR = new InputStreamReader(
                    SerialNumberProcess.getInputStream());
            BufferedReader br = new BufferedReader(ISR);
            for(int i=0;i<3;i++){
                serial = br.readLine().trim();
                SerialNumberProcess.waitFor();
            }
            br.close();
        }
        catch (Exception e) {
            e.printStackTrace();
            serial = null;
        }
        return serial;
    }
}
