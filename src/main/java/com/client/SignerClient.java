package com.client;

import com.itextpdf.text.pdf.security.*;
import com.server.HttpRequest;
import org.apache.commons.codec.Charsets;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class SignerClient {
    public static final String PreSignURL = "http://localhost:8080/PreSign";
    public static final String PostSignURL = "http://localhost:8080/PostSign";
    public static final String CERT = "src/main/resources/gdca.cer";
    public static final String PFX = "src/main/resources/fy-new2.pfx";
    public static final String PROPERTY = "src/main/resources/key.property";
    public static final String DEST = "results/signed.pdf";
    static String key_password;

    public static void readProperty(String propertyPath)
    {
        Properties properties = new Properties();
        try {
            properties.load(new FileInputStream(propertyPath));
            key_password = properties.getProperty("PASSWORD");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String getbase64Cert()
    {
        return "MIIFFTCCA/2gAwIBAgIIc4kcub6Ex5gwDQYJKoZIhvcNAQELBQAwbzELMAkGA1UE" +
                "BhMCQ04xOTA3BgNVBAoMMEdsb2JhbCBEaWdpdGFsIEN5YmVyc2VjdXJpdHkgQXV0" +
                "aG9yaXR5IENvLiwgTHRkLjElMCMGA1UEAwwcR0RDQSBUcnVzdEFVVEggUjQgR2Vu" +
                "ZXJpYyBDQTAeFw0xNzA4MzEwODU1NTlaFw0xOTA5MDEwODU1NTlaMIGkMQswCQYD" +
                "VQQGEwJDTjESMBAGA1UECAwJ5YyX5Lqs5biCMRIwEAYDVQQHDAnljJfkuqzluIIx" +
                "JzAlBgNVBAoMHuWMl+S6rOaeq+eOieenkeaKgOaciemZkOWFrOWPuDEbMBkGA1UE" +
                "CwwS5oC757uP55CG5Yqe5YWs5a6kMScwJQYDVQQDDB7ljJfkuqzmnqvnjonnp5Hm" +
                "ioDmnInpmZDlhazlj7gwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5" +
                "bMmsNuXMelkFPWrMMYJz5Th7g8TrLuCDVlMhOS7222QIfkPve4eKArKz+FyAasgD" +
                "o8bq+3eBTIq256PwNQavIHjinbCPqWoBG681KViOs0y2CHCpkQUVblogzDtH1qwz" +
                "p/v5n9SU/7fYxNupS0OGQygFDaV49WZ24vBNEZ2WAAuceV1AKU8+6bc3igWz2u5i" +
                "IHqjJpV/tv4VoZdsvaGFA12fYKeEkhZLamAEG0yccwHrXS3wzrIRYHTT9MaVAt3A" +
                "HzyhI3mtl111vagl72nQ76Zd7kUA1Kwq40ErE7EzcrjG8Lp/m7yPyLs6irerYWZI" +
                "T+Hk7BxEzSIn9gBErv35AgMBAAGjggF9MIIBeTCBgwYIKwYBBQUHAQEEdzB1MEgG" +
                "CCsGAQUFBzAChjxodHRwOi8vd3d3LmdkY2EuY29tLmNuL2NlcnQvR0RDQV9UcnVz" +
                "dEFVVEhfUjRfR2VuZXJpY19DQS5kZXIwKQYIKwYBBQUHMAGGHWh0dHA6Ly9vY3Nw" +
                "Mi5nZGNhLmNvbS5jbi9vY3NwMB0GA1UdDgQWBBQk3yVI4/Rc4bP7njDONJRMMcSB" +
                "EjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFNP+7mGAwJmQWW3WJFXy/8DrJxfs" +
                "MEUGA1UdIAQ+MDwwOgYKKoEchu8vAQEBAjAsMCoGCCsGAQUFBwIBFh5odHRwOi8v" +
                "d3d3LmdkY2EuY29tLmNuL2Nwcy9jcHMwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDov" +
                "L2NybC5nZGNhLmNvbS5jbi9jcmwvR0RDQV9UcnVzdEFVVEhfUjRfR2VuZXJpY19D" +
                "QS5jcmwwDgYDVR0PAQH/BAQDAgTwMA0GCSqGSIb3DQEBCwUAA4IBAQAdQlwngkre" +
                "BiImPKqsft7rrR1RSMNziXZaD+lhmPpkDYrV1M2sfASUW82j1Ju7BCWhDHitFzcO" +
                "7wKCguLG+fEyGgnqyARzQ556mVIJL1KXKrUjHeg15xZlVIyN3RxaecgZ9N0POah8" +
                "XTtijgGwty+YLgSJtZoyqJVzVJE71R+PZl3g5otoCtLlpTCbGP6RcNiwZFGDk8nK" +
                "PnX713oodGo1h5wcMSqiyQ0CNF7xyIisT86NevBo57FcWDcRSjZHmIZ0oTgEVnKz" +
                "UULPz+72qlZs4mkImcy26AyX1nti+KgOQuqjIodKk3pr9OfgQD9ZfipzkgBk/rZL" +
                "zXQoDkC7lJqp";
    }

    public String getHash(String cert) throws IOException {
        // write certificate to connection
        JSONObject obj_send = new JSONObject();
        obj_send.put("cert", getbase64Cert());
        String param = obj_send.toString();
        String s = HttpRequest.sendPost(PreSignURL, param);
        System.out.println(s);

        JSONObject obj = new JSONObject(s);
        String base64hash = obj.getString("hash");

        System.out.println(base64hash);
        return base64hash;
    }

    public byte[] signed_hash(byte[] hash, PrivateKey pk, Certificate[] chain) throws GeneralSecurityException {
        PrivateKeySignature signature = new PrivateKeySignature(pk, "SHA256", "BC");
        BouncyCastleDigest digest = new BouncyCastleDigest();
        PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", null, digest, false);

        // ocsp request
        OCSPVerifier ocspVerifier = new OCSPVerifier(null, null);
        OcspClient ocspClient = new OcspClientBouncyCastle(ocspVerifier);
        byte[] ocsp = null;
        if (chain.length >= 2 && ocspClient != null) {
            ocsp = ocspClient.getEncoded((X509Certificate)chain[0], (X509Certificate)chain[1], (String)null);
        }

        byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, ocsp, null, MakeSignature.CryptoStandard.CMS);
        byte[] extSignature = signature.sign(sh);
        sgn.setExternalDigest(extSignature, null, signature.getEncryptionAlgorithm());
        // timestamp
        TSAClientBouncyCastle tsaClient = new TSAClientBouncyCastle("http://timestamp.entrust.net/TSS/JavaHttpTS", null, null);
        return sgn.getEncodedPKCS7(hash, tsaClient, ocsp, null, MakeSignature.CryptoStandard.CMS);
    }

    public void getSignedPDF(byte[] data, String file) throws IOException {
        JSONObject obj_send = new JSONObject();
        obj_send.put("signed_hash", new String(Base64.encode(data), Charsets.UTF_8));
        String param = obj_send.toString();
        String s = HttpRequest.sendPost(PostSignURL, param);
        System.out.println(s);
    }

    public static void main(String args[]) throws IOException, GeneralSecurityException {
        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);
        readProperty(PROPERTY);
        // we load our private key from the key store
        KeyStore ks = KeyStore.getInstance("pkcs12", "BC");
        FileInputStream input = new FileInputStream(PFX);
        ks.load(input, key_password.toCharArray());
        String alias = (String)ks.aliases().nextElement();
        Certificate[] chain = ks.getCertificateChain(alias);
        PrivateKey pk = (PrivateKey) ks.getKey(alias, key_password.toCharArray());

        SignerClient sc = new SignerClient();

        //1. get hash from PreSign
        String base64hash = null;
        try {
            base64hash = sc.getHash(CERT);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("base64 hash:\n" + base64hash);

        //2. sign the hash
        byte[] hash = Base64.decode(base64hash);
        byte[] hh_sign = sc.signed_hash(hash,  pk,  chain);
        System.out.println("base64 signed hash:\n" + new String(Base64.encode(hh_sign), Charsets.UTF_8));

        //3. post signed hash to server and get the signed PDF
        sc.getSignedPDF(hh_sign, DEST);

    }
}
