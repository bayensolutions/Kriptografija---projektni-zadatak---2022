import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestHolder;

public class Cryptography {

    public static void generateKeyPair(String path, String username, String password) throws NoSuchAlgorithmException, FileNotFoundException, IOException, InvalidKeySpecException {
        ProcessBuilder builder = new ProcessBuilder("cmd.exe", "/c","openssl genrsa -aes256 -out "+username+".key"+" -passout pass:"+password+" 2048");
        builder.redirectErrorStream(true);
        builder.directory(new File(path));
        Process p = builder.start();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
       
       
       
        /*
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        PEMWriter pw=new PEMWriter(new FileWriter(path+"\\"+username+".key"));
        pw.writeObject(privateKey);
        pw.close();
        */
    }

    public static X509Certificate getX509(File certificateFile) throws CertificateException, FileNotFoundException {
        FileInputStream f = new FileInputStream(certificateFile.getAbsolutePath());
        CertificateFactory c = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) c.generateCertificate(f);
        return x509Certificate;
    }

    public static X509CRL getCRL(File CRLFile) throws Exception {
        FileInputStream f = new FileInputStream(CRLFile.getAbsolutePath());
        CertificateFactory c = CertificateFactory.getInstance("X.509");
        X509CRL CRLList = (X509CRL) c.generateCRL(f);
        return CRLList;
    }

    public static PrivateKey getPrivateKey(String filename) throws Exception {

        return getPrivateKey(filename);
    }

    public static void createCertificate(String CAPrivateKeyPath, String username, String password, String country,
            String state,
            String locality, String organizationalUnit, String organization) throws NoSuchAlgorithmException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String subject = "CN=" + username + ", O=" + organization + ", OU=" + organizationalUnit + ", L=" + locality
                + ", ST=" + state + ", C=" + country;

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        PKCS10CertificationRequestBuilder req = new PKCS10CertificationRequestBuilder(new X500Name(subject),
                subjectPublicKeyInfo);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");

        // ContentSigner contentSigner =
        // csBuilder.build(getPrivateKey(CAPrivateKeyPath,"sigurnost"));
        // PKCS10CertificationRequestHolder request = req.build(contentSigner);
        // X509Certificate certificate = signCertificateRequest(request,
        // subjectPublicKeyInfo, signer, contentSigner);
        // String certificatePath = certFolderPath + userName + ".der";
        // writeCertificate(certificate, new File(certificatePath));

    }

}
