import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

    public static final String usersPath = "C:\\Users\\Korisnik\\Desktop\\KRIPTOGRAFIJA_2022\\Quiz\\users\\users.txt";
    public static final String certificatesPath = "C:\\Users\\Korisnik\\Desktop\\KRIPTOGRAFIJA_2022\\Quiz\\certificates";
    public static final String CAPath="C:\\Users\\Korisnik\\Desktop\\KRIPTOGRAFIJA_2022\\Quiz\\certificates\\ROOT CA\\trusted certificates";

    static File users = new File(usersPath);

    private static java.io.OutputStream outputStream;

    public static void main(String[] args) throws Exception {
        createMenu();
    }

    public static void createMenu() throws Exception {
        boolean isExit = false;
        while (!isExit) {
            System.out.println("*********************************");
            System.out.println("* Choose the option:            *");
            System.out.println("* 1. Register                   *");
            System.out.println("* 2. Login                      *");
            System.out.println("* 3. Exit                       *");
            System.out.println("*********************************");
            System.out.print("Your selection: ");
            Scanner s = new Scanner(System.in);
            int option = s.nextInt();
            switch (option) {
                case 1:
                    register();
                    break;
                case 2:
                    System.out.println("Login");
                    break;
                case 3:
                    System.out.println("Goodbye.");
                    isExit = true;
                default:
                    System.out.println("You chose non-existent option. Select 1, 2 or 3.");
            }
        }
    }

    public static void register() throws Exception {
        Boolean incorrectRegistration = false;
        System.out.println("REGISTRATION");
        Scanner entry = new Scanner(System.in);
        System.out.print("Input username: ");
        String username = entry.nextLine();
        System.out.print("Input password: ");
        String password = entry.nextLine();

        Scanner fileScanner = new Scanner(users);
        while (fileScanner.hasNextLine()) {
            String line = fileScanner.nextLine();
            if (line.contains(username)) {
                System.out.println("Username " + username + " is already used. Please try with the another one.");
                incorrectRegistration = true;
                break;
            }
        }

        if (username.length() < 8 && !incorrectRegistration) {
            System.out.println("The username must contain at least 8 characters.");
            incorrectRegistration = true;
        }

        if (!incorrectRegistration) {

            registerInBase(username, password);

            Random random = new Random();
            int number = random.nextInt(2) + 1;

            Cryptography.generateKeyPair(CAPath+"\\CA"+number+"\\info\\keys",username,password);


            

            /*PrivateKey pk = Cryptography.getPrivateKey(
                    "C:\\Users\\Korisnik\\Desktop\\KRIPTOGRAFIJA_2022\\Quiz\\certificates\\ROOT CA\\trusted certificates\\CA"
                            + number + "\\info\\private\\ca" + number + ".key");
            System.out.println(pk.getEncoded().toString());
*/
            /*
             * Cryptography.
             * createCertificate("C:\\Users\\Korisnik\\Desktop\\KRIPTOGRAFIJA_2022\\Quiz\\certificates\\ROOT CA\\trusted certificates\\CA"
             * + number +
             * "\\info\\"+number+".pem",username, password, "BA", "RS", "BL", "UNIBL", "ETF"
             * );
             * 
             * File certificateFile=new
             * File("C:\\Users\\Korisnik\\Desktop\\KRIPTOGRAFIJA_2022\\Quiz\\certificates\\ROOT CA\\trusted certificates\\CA"
             * + number + "\\info\\certs\\"+username+".crt");
             * File CRLFile=new
             * File("C:\\Users\\Korisnik\\Desktop\\KRIPTOGRAFIJA_2022\\Quiz\\certificates\\ROOT CA\\trusted certificates\\CA"
             * + number + "\\info\\crl\\lista.pem");
             * File CAFile=new
             * File("C:\\Users\\Korisnik\\Desktop\\KRIPTOGRAFIJA_2022\\Quiz\\certificates\\ROOT CA\\trusted certificates\\CA"
             * + number + "\\info\\ca"+number+".pem");
             * 
             * X509Certificate x509Certificate=Cryptography.getX509(certificateFile);
             * X509CRL CRLList = Cryptography.getCRL(CRLFile);
             * X509Certificate CACertificate = Cryptography.getX509(CAFile);
             * 
             * PublicKey publicKeyCA = CACertificate.getPublicKey();
             * 
             * 
             */

        }

    }

    public static void registerInBase(String username, String password) throws IOException {
        String salt = "";
        for (int i = 0; i < 2; i++) {
            salt += username;
        }
        ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c","openssl passwd -5 -salt " + salt + " " + password);
        builder.redirectErrorStream(true);
        builder.directory(new File(certificatesPath));
        Process p = builder.start();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String hash = r.readLine();
        Files.write(Paths.get(usersPath), (username + " " + hash + "\n").getBytes(), StandardOpenOption.APPEND);
    }

}
