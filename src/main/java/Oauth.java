import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.awt.Desktop;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.*;

public class Oauth {
    private final String consumerKey = ClientCred.CONSUMER_KEY;
    private final String secretKey = ClientCred.SECRET_KEY;

    private static String tokenKey = "";
    private static String tokenSecret = "";



    private static String makeBaseString(String uri, String method, TreeMap<String, String> oauthHeader) throws UnsupportedEncodingException {
        String returnString = method.toUpperCase();
        returnString += "&";
        returnString += URLEncoder.encode("https://api.schoology.com/v1/" + uri, StandardCharsets.UTF_8.toString());
        returnString += "&";

        for(Map.Entry<String, String> entry : oauthHeader.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            returnString = returnString.concat(URLEncoder.encode(entry.getKey() + "=" + entry.getValue(), StandardCharsets.UTF_8.toString()));
        }


        return returnString;
    }

    //For the makeOauthSig method
    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();

        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }

    //For the makeOauthSig method: Generates the HMAC-SHA1 hash
    private static String calculateRFC2104HMAC(String data, String key)
            throws NoSuchAlgorithmException, InvalidKeyException
    {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);
        return toHexString(mac.doFinal(data.getBytes()));
    }

    private static String makeOauthSig(String url, String method, TreeMap<String, String> oauthHeader)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, UnsupportedEncodingException {
        String baseString = makeBaseString(url, method, oauthHeader);
        String key = URLEncoder.encode((ClientCred.SECRET_KEY + "&" + tokenSecret), StandardCharsets.UTF_8.toString());
        return calculateRFC2104HMAC(baseString, key);
    }

    public static String makeOauthHeader(String uri, String method) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //Create the timestamp and nonce
        long timestamp = System.currentTimeMillis()/1000;
        UUID nonce = UUID.randomUUID();

        //Initialize the hashmap with all necessary values in the Authorization header
        TreeMap<String, String> oauthHeader = new TreeMap<String, String>() {{
           put("oauth_consumer_key", ClientCred.CONSUMER_KEY);
           put("oauth_nonce", nonce.toString());
           put("oauth_signature_method", "HMAC-SHA1");
           put("oauth_timestamp", String.valueOf(timestamp));
           put("oauth_token", tokenKey);
           put("oauth_callback", "oob");
           put("oauth_version", "1.0");
        }};


        //Call makeOauthSig passing the HashMap, url, and method (is a string)
        oauthHeader.put("oauth_signature", makeOauthSig(uri, method, oauthHeader));

        //Iterate through the HashMap and assemble the oauth header
        String returnHeader = "Oauth realm=\"Schoology API\",";
        for(Map.Entry<String, String> entry : oauthHeader.entrySet()) {
            returnHeader = returnHeader.concat(entry.getKey() + "=\"" + entry.getValue() + "\",");
        }
        return returnHeader;
    }

    // /oauth/request_token
    private static String[] getTempCredentials() {
        /*
        Make a request to the uri endpoint declared above and parse the response to get the temporary credentials for the oauth handshake.
         */

        /* More testing code that will be necessary when developing the final method

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .header("Authorization", oauthHeader)
                .header("accept", "application/x-www-form-urlencoded")
                .uri(new URI("https://api.schoology.com/v1/oauth/request_token"))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
         */
        return null;
    }

    // /oauth/authorize?
    private static String[] authorizeTempCredentials() {
        /*
        Uses the java.awt.Desktop import to open the default web browser to allow the user to authorize the temporary tokens.
        For now will take input from the command line using a scanner but later will use the GUI to get the token and authorizer from the user.
         */
        return null;
    }

    // /oauth/access_token
    private static String[] getToken() {
        /*
        After the previous two functions have been called, use the temporary token and the token authorizer to make a request to the API for the permanent oauth tokens.
         */
        return null;
    }

    public static void Authorize() {
        //Call the getTempCredentials, authorizeTempCredentials, and getToken methods in order to complete the oauth handshake with the server.
    }
}