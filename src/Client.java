import javax.crypto.*;
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
import java.util.ArrayList;
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

    public static LicenceManager licenceManager;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException {
        motherboardSerialNumber = getWindowsMotherBoardSerialNumber(); // os dependent - must be implemented hard-coded
        diskSerialNumber = getSerialNumber("D"); // os dependent - must be implemented hard-coded, 4810-E58D for windows machine
        username = "ImreAndCagla"; // static
        serialNumber = "1234-5678-9012"; // static
        MACAddress = getMACAddress(); // the function to receive mac address can be implemented independent of the platform
        KeyFactory kf = KeyFactory.getInstance("RSA");
        publicKey = kf.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(Path.of("src/keys/public.key"))));
        File f = new File("licence.txt");
        licenceManager=new LicenceManager();
        if(f.exists() && !f.isDirectory()) {

        }else {
            sendEncryptedLicenseContent(licenceManager);
             byte[] managersLicence=licenceManager.getSignature();//lcence managerden signature alındı
            System.out.println(verifyLicense(managersLicence));
        }
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    private static String getMACAddress() throws SocketException, UnknownHostException {
        InetAddress localHost = InetAddress.getLocalHost(); // get address for machine's local host
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
        return username + "$" + serialNumber + "$" + MACAddress + "$" + diskSerialNumber + "$" + motherboardSerialNumber;
    }

    private static List<byte[]> EncryptLicenseContent() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //generate a symmetric key
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey symmetricKey = generator.generateKey();
        //encrypt the content with symmetric key
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
        byte[] encryptedText = cipher.doFinal(getLicenceContent().getBytes());

        // encrypt the symmetric key with public key
        Cipher cipher2 = Cipher.getInstance("RSA");
        cipher2.init(Cipher.PUBLIC_KEY, publicKey);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey.getEncoded());
        List<byte[]> encryptedLicenseContentWithKey = new ArrayList<byte[]>();
        encryptedLicenseContentWithKey.add(encryptedText);
        encryptedLicenseContentWithKey.add(encryptedSymmetricKey);
        return encryptedLicenseContentWithKey;
    }

    public static void sendEncryptedLicenseContent(LicenceManager licenceManager) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException, SignatureException {
        licenceManager.setEncryptedLicenseContent(EncryptLicenseContent());
    }

    private static String HashLicenseContent() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5"); // take the hash of the license content with MD5
        byte[] hash = digest.digest(getLicenceContent().getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(hash), StandardCharsets.UTF_8); // convert the hashed bytes to string
    }

    // https://stackoverflow.com/questions/7224626/how-to-sign-string-with-private-key
    public static boolean verifyLicense(byte[] licenceSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(publicKey); // verify signature with public key
        signature.update(HashLicenseContent().getBytes());
        return signature.verify(licenceSignature);
    }

    public static String getSerialNumber(String letter) throws IOException {
        String line = null;
        String serial = null;
        Process process = Runtime.getRuntime().exec("cmd /c vol "+letter+":");
        BufferedReader in = new BufferedReader(
                new InputStreamReader(process.getInputStream()) );
        while ((line = in.readLine()) != null) {
            if(line.toLowerCase().contains("serial number")){
                String[] strings = line.split(" ");
                serial = strings[strings.length-1];
            }
        }
        in.close();
        return serial;
    }

    public static String getWindowsMotherBoardSerialNumber()
    {

        // command to be executed on the terminal
        String command = "wmic baseboard get serialnumber";
        // variable to store the Serial Number
        String serialNumber = null;
        // try block
        try {

            // declaring the process to run the command
            Process SerialNumberProcess
                    = Runtime.getRuntime().exec(command);
            // getting the input stream using
            // InputStreamReader using Serial Number Process
            InputStreamReader ISR = new InputStreamReader(
                    SerialNumberProcess.getInputStream());
            // declaring the Buffered Reader
            BufferedReader br = new BufferedReader(ISR);
            // reading the serial number using
            // Buffered Reader
            for(int i=0;i<3;i++){
                serialNumber = br.readLine().trim();
                SerialNumberProcess.waitFor();
            }
            // closing the Buffered Reader
            br.close();
        }

        // catch block
        catch (Exception e) {
            // printing the exception
            e.printStackTrace();
            // giving the serial number the value null
            serialNumber = null;
        }
        // returning the serial number
        return serialNumber;
    }
}
