package com.example.authserverdemo.security.jwt;

import com.example.authserverdemo.config.AppProperties;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Component
public class JWTokenKeyProvider {

    private final AppProperties appProperties;

    public JWTokenKeyProvider(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    public PrivateKey getPrivateKey() {
        PrivateKey privateKey = null;

        try {
            byte[] bytes = parsePEMFile(new File(appProperties.getAuth().getPrivateKey()));

            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the private key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the private key");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public PublicKey getPublicKey() {
        PublicKey publicKey = null;

        try {
            byte[] bytes = parsePEMFile(new File(appProperties.getAuth().getPublicKey()));

            KeyFactory kf = KeyFactory.getInstance("RSA");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the public key");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    private byte[] parsePEMFile(File pemFile) throws IOException {
        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }
        PemReader reader = new PemReader(new FileReader(pemFile));
        PemObject pemObject = reader.readPemObject();
        byte[] content = pemObject.getContent();
        reader.close();
        return content;
    }
}
