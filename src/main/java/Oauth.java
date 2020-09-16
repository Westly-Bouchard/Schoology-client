import java.net.*;
import java.awt.Desktop;
import java.util.*;

public class Oauth {
    private final String consumerKey = ClientCred.CONSUMER_KEY;
    private final String secretKey = ClientCred.SECRET_KEY;

    //callback should always be oob
    private static String makeBaseString(String url, String method, HashMap<String, String> oauthHeader) {
        return null;
    }

    private static String makeOauthSig(String url, String method, HashMap<String, String> oauthHeader) {
        //Will call makeBaseString()
        return null;
    }

    public static String makeOauthHeader(String url, String method, String body) {
        HashMap<String, String> oauthHeader;
        //Initialize the hashmap with all necessary values in the Authorization header

        /*
        Call makeOauthSig passing the HashMap, url, and method (is a string)
        Iterate through the HashMap and assemble the oauth header
        return the header in the form of a string
         */

        /* Just some testing code that will be useful when writing the actual method
        long timestamp = System.currentTimeMillis() / 1000;
        UUID nonce = UUID.randomUUID();

        String oauthHeader = "Oauth realm=\"Schoology API\"," +
                "oauth_consumer_key=" + ClientCred.CONSUMER_KEY + "," +
                "oauth_nonce=\"" + nonce + "\"," +
                "oauth_signature_method=\"HMAC-SHA1\"," +
                "oauth_timestamp=\"" + timestamp + "\"," +
                "oauth_token=\"\"," +
                "oauth_version=\"1.0\"," +
                "oauth_signature=\"" + ClientCred.SECRET_KEY + "\"";
         */
        return null;
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