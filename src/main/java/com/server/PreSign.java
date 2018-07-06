package com.server;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;
import org.apache.commons.codec.Charsets;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;

public class PreSign extends HttpServlet {
    private String message;

    public void init() throws ServletException
    {
        message = "Pre Sign New";
    }

    // Decode base64 encoded certificate
    public Certificate buildCert(String base64)
    {
        // Remove the first and last lines if exists
        String CertPEM = base64.replace("-----BEGIN CERTIFICATE-----", "");
        CertPEM = CertPEM.replace("-----END CERTIFICATE-----", "");
        System.out.println(CertPEM);

        // decode base64 string
        byte [] encoded = Base64.decode(CertPEM);

        // build Certificate
        CertificateFactory certFactory = null;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        InputStream in = new ByteArrayInputStream(encoded);
        X509Certificate cert = null;
        try {
            cert = (X509Certificate)certFactory.generateCertificate(in);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return cert;
    }

    // Build certificate chain
    // Root CA is GDCA_Public_CA1.pem
    public Certificate[] buildChain(String[] certs)
    {
        System.out.println("certs.length = " + certs.length);
        Certificate[] chain = new Certificate[certs.length];
        for (int i=0; i<certs.length; ++i)
        {
            chain[i] = buildCert(certs[i]);
        }
        return chain;
    }

    public void doGet(HttpServletRequest req,
                      HttpServletResponse resp)
            throws ServletException, IOException
    {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
        out.println("<h1>" + message + "</h1>");
        out.println("<h1>" + System.getProperty("user.dir") + "</h1>");
        out.println("<h1>" + df.format(new Date()) + "</h1>");
    }

    public void doPost(HttpServletRequest req,
                      HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        req.setCharacterEncoding("UTF-8");

        /**
         * 接收json
         */
        BufferedReader reader = req.getReader();
        String json = reader.readLine();
        JSONObject obj = new JSONObject(json);
        String cert = obj.getString("cert");
        reader.close();

        // build chain
        Certificate[] chain = new Certificate[1];
        chain = buildChain(new String[]{cert});

        // create empty signature
        PdfReader pdfReader = new PdfReader("test.pdf");
        FileOutputStream os = new FileOutputStream("temp.pdf");
        byte[] hash = null;
        try {
            PdfStamper stamper = PdfStamper.createSignature(pdfReader, os, '\0');
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig1");
            appearance.setCertificate(chain[0]);
            ExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            MakeSignature.signExternalContainer(appearance, external, 8192 * 4);
            InputStream inp = appearance.getRangeStream();
            BouncyCastleDigest digest = new BouncyCastleDigest();
            hash = DigestAlgorithms.digest(inp, digest.getMessageDigest("SHA256"));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (DocumentException e) {
            e.printStackTrace();
        }
        String base64hash = new String(Base64.encode(hash), Charsets.UTF_8);

        /**
         * 返回json
         */
        PrintWriter out = resp.getWriter();
        out.write("{\"hash\":" + "\"" + base64hash + "\"" + "}");
        out.close();
    }
}
