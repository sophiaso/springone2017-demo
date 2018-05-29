/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */
package sample.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.aad.adal4j.UserAssertion;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import javax.naming.ServiceUnavailableException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class AzureADGraphClient {

    public static String getUserMembershipsV1(String accessToken, String aadMembershipRestAPI) throws IOException {
        final URL url = new URL(aadMembershipRestAPI);

        final HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("api-version", "1.6");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setRequestProperty("Accept", "application/json;odata=minimalmetadata");
        final String responseInJson = getResponseStringFromConn(conn);
        final int responseCode = conn.getResponseCode();
        if (responseCode == HTTPResponse.SC_OK) {
            return responseInJson;
        } else {
            throw new IllegalStateException("Response is not " + HTTPResponse.SC_OK +
                    ", response json: " + responseInJson);
        }
    }

    private static String getResponseStringFromConn(HttpURLConnection conn) throws IOException {

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            final StringBuilder stringBuffer = new StringBuilder();
            String line = "";
            while ((line = reader.readLine()) != null) {
                stringBuffer.append(line);
            }
            return stringBuffer.toString();
        }
    }

    public static AuthenticationResult acquireTokenForGraphApi(AzureADConfig azureADConfig,
                                                               String idToken, String clientId, String clientSecret)
            throws MalformedURLException, ServiceUnavailableException, InterruptedException, ExecutionException {
        final ClientCredential credential = new ClientCredential(clientId, clientSecret);
        final UserAssertion assertion = new UserAssertion(idToken);

        AuthenticationResult result = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            final AuthenticationContext context = new AuthenticationContext(
                    azureADConfig.getAadSiginUrl() + azureADConfig.getTenantId() + "/",
                    true, service);

            final Future<AuthenticationResult> future = context
                    .acquireToken(azureADConfig.getGraphAPIUrl(), assertion, credential, null);
            result = future.get();
        } finally {
            if (service != null) {
                service.shutdown();
            }
        }

        if (result == null) {
            throw new ServiceUnavailableException(
                    "unable to acquire on-behalf-of token for client " + clientId);
        }
        return result;
    }

    public static List<UserGroup> getGroups(String graphApiToken, String memberUrl) {
        try {
            return loadUserGroups(graphApiToken, memberUrl);
        } catch (IOException ioe) {
            throw new IllegalStateException("Failed to load user groups from " + memberUrl, ioe);
        }
    }

    private static List<UserGroup> loadUserGroups(String graphApiToken, String memberUrl) throws IOException {
        final String responseInJson = getUserMembershipsV1(graphApiToken, memberUrl);
        final List<UserGroup> lUserGroups = new ArrayList<>();
        final ObjectMapper objectMapper = new ObjectMapper();
        final JsonNode rootNode = objectMapper.readValue(responseInJson, JsonNode.class);
        final JsonNode valuesNode = rootNode.get("value");

        if(valuesNode != null) {
            valuesNode.forEach(node -> {
                if (node != null && node.get("objectType").asText().equals("Group")) {
                    UserGroup group = new UserGroup(node.get("objectId").asText(), node.get("displayName").asText());
                    lUserGroups.add(group);
                }
            });
        }

        return lUserGroups;
    }
}
