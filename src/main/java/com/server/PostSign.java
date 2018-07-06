package com.server;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.MakeSignature;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class PostSign extends HttpServlet {
    private String message;

    class MyExternalSignatureContainer implements ExternalSignatureContainer {

        protected byte[] sig;

        public MyExternalSignatureContainer(byte[] sig) {
            this.sig = sig;
        }

        public byte[] sign(InputStream is) {
            return sig;
        }

        public void modifySigningDictionary(PdfDictionary signDic) {
        }

    }

    public void init() throws ServletException
    {
        message = "Post Sign";
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

        BufferedReader reader = req.getReader();
        String json = reader.readLine();
        JSONObject obj = new JSONObject(json);
        String base64_hh_signed = obj.getString("signed_hash");
        reader.close();

        byte[] signed_hh = Base64.decode(base64_hh_signed);

        PdfReader pdfReader = new PdfReader("temp.pdf");
        FileOutputStream os = new FileOutputStream("signed.pdf");
        ExternalSignatureContainer external = new MyExternalSignatureContainer(signed_hh);
        try {
            MakeSignature.signDeferred(pdfReader, "sig1", os, external);
        } catch (DocumentException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        PrintWriter out = resp.getWriter();
        String r = "success";
        out.write("{\"result\":" + "\"" + r + "\"" + "}");
        out.close();

    }
}
