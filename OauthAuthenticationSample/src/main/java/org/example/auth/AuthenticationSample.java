package org.example.auth;

import okhttp3.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.time.Instant;

public class AuthenticationSample {
    private static final Charset ENC = StandardCharsets.UTF_8;
    private static String key = "{{your client ID}}";
    private static String secret = "{{your client secret}}";
    private static Base64 base64 = new Base64();

    public static void main(String[] args) throws Exception {

        String authenticationURL = "https://account.api.here.com/oauth2/token";
        String nonce = gen(17);
        long timeSinceEpoch = Instant.now().getEpochSecond();

        OkHttpClient client = new OkHttpClient().newBuilder()
                .build();
        MediaType mediaType = MediaType.parse("application/x-www-form-urlencoded");
        RequestBody body = RequestBody.create(mediaType, "grant_type=client_credentials");


        StringBuilder sb = new StringBuilder("grant_type=client_credentials");
        sb.append("&oauth_consumer_key=").append(URLEncoder.encode(key, ENC));
        sb.append("&oauth_nonce=").append(nonce);
        sb.append("&oauth_signature_method=").append(URLEncoder.encode("HMAC-SHA256", ENC));
        sb.append("&oauth_timestamp=").append(timeSinceEpoch);
        sb.append("&oauth_version=1.0");

        StringBuilder base = new StringBuilder();
        base.append("POST&");
        base.append(URLEncoder.encode(authenticationURL, ENC));
        base.append("&");
        base.append(URLEncoder.encode(sb.toString(), ENC));
        String normalizedString = base.toString();
        String signingKey = URLEncoder.encode(secret, ENC) + "&";

        System.out.println(MessageFormat.format("Creating signature with normalizedString : {0}, signingKey: {1}", normalizedString, signingKey));


        // generate the oauth_signature
        String signature = encode(signingKey, normalizedString);

        String signingMethod = URLEncoder.encode("HMAC-SHA256", ENC);
        String authHeader = "OAuth oauth_consumer_key=\"" + URLEncoder.encode(key, ENC) + "\"," +
                "oauth_signature_method=\"" + signingMethod + "\"," +
                "oauth_timestamp=\"" + timeSinceEpoch + "\"," +
                "oauth_nonce=\"" + nonce + "\"," +
                "oauth_version=\"1.0\"," +
                "oauth_signature=\"" + URLEncoder.encode(signature, ENC) + "\"";

        Request request = new Request.Builder()
                .url(authenticationURL)
                .method("POST", body)
                .addHeader("Authorization", authHeader)
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .build();
        try {
            Response response = client.newCall(request).execute();
            System.out.println(response.body().string());
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static String gen(int length) {
        StringBuffer sb = new StringBuffer();
        for (int i = length; i > 0; i -= 12) {
            int n = Math.min(12, Math.abs(i));
            sb.append(StringUtils.leftPad(Long.toString(Math.round(Math.random() * Math.pow(36, n)), 36), n, '0'));
        }
        return sb.toString();
    }

    public static String encode(String key, String data) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
        sha256_HMAC.init(secret_key);

        return Base64.encodeBase64String(sha256_HMAC.doFinal(data.getBytes("UTF-8")));
    }

}
