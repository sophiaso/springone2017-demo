/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.aad.adal4j.UserAssertion;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import javax.naming.ServiceUnavailableException;
import javax.validation.constraints.NotEmpty;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {
	@Value("${azure.activedirectory.graphapiurl:https://graph.windows.net/}")
	private String graphAPIUrl;

	@Value("${azure.activedirectory.aadsiginurl:https://login.microsoftonline.com/}")
	private String aadSiginUrl;

	@Value("${azure.activedirectory.aadmemberurl:https://graph.windows.net/me/memberOf}")
	private String aadMemberUrl;

	@Value("${azure.activedirectory.tenantid}")
	@NotEmpty
	private String tenantId;

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2Login()
					.userInfoEndpoint()
						.oidcUserService(this.oidcUserService());
	}


	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		final OidcUserService delegate = new OidcUserService();

		return (userRequest) -> {
			// Delegate to the default implementation for loading a user
			OidcUser oidcUser = delegate.loadUser(userRequest);

			OidcIdToken idToken = userRequest.getIdToken();
			String clientId = userRequest.getClientRegistration().getClientId();
			String clientSecret = userRequest.getClientRegistration().getClientSecret();
			String graphApiToken;

			try {
				graphApiToken = acquireTokenForGraphApi(
						idToken.getTokenValue().toString(), clientId, clientSecret).getAccessToken();
			} catch (Exception e) {
				throw new IllegalStateException(e);
			}

			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

			// 1) Fetch the authority information from the protected resource using accessToken
			List<UserGroup> groups = getGroups(graphApiToken);
			// 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities
			mappedAuthorities = groups.stream()
					.map(userGroup -> new SimpleGrantedAuthority("ROLE_" + userGroup.getDisplayName()))
					.collect(Collectors.toCollection(LinkedHashSet::new));
			// 3) Create a copy of oidcUser but use the mappedAuthorities instead
			oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

			return oidcUser;
		};
	}

	private AuthenticationResult acquireTokenForGraphApi(String idToken, String clientId, String clientSecret)
			throws MalformedURLException, ServiceUnavailableException, InterruptedException, ExecutionException {
		final ClientCredential credential = new ClientCredential(clientId, clientSecret);
		final UserAssertion assertion = new UserAssertion(idToken);

		AuthenticationResult result = null;
		ExecutorService service = null;
		try {
			service = Executors.newFixedThreadPool(1);
			final AuthenticationContext context = new AuthenticationContext(
					aadSiginUrl + tenantId + "/", true, service);
			final Future<AuthenticationResult> future = context
					.acquireToken(graphAPIUrl, assertion, credential, null);
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

	private List<UserGroup> getGroups(String graphApiToken) {
		try {
			return loadUserGroups(graphApiToken);
		} catch (IOException ioe) {
			throw new IllegalStateException(ioe);
		}
	}

	private List<UserGroup> loadUserGroups(String graphApiToken) throws IOException {
		final String responseInJson =
				AzureADGraphClient.getUserMembershipsV1(graphApiToken, aadMemberUrl);
		final List<UserGroup> lUserGroups = new ArrayList<>();
		final ObjectMapper objectMapper = new ObjectMapper();
		final JsonNode rootNode = objectMapper.readValue(responseInJson, JsonNode.class);
		final JsonNode valuesNode = rootNode.get("value");
		int i = 0;
		while (valuesNode != null
				&& valuesNode.get(i) != null) {
			if (valuesNode.get(i).get("objectType").asText().equals("Group")) {
				lUserGroups.add(new UserGroup(
						valuesNode.get(i).get("objectId").asText(),
						valuesNode.get(i).get("displayName").asText()));
			}
			i++;
		}
		return lUserGroups;
	}

	@Bean
	public OAuth2AuthorizedClientService authorizedClientService() {
		return new InMemoryOAuth2AuthorizedClientService(this.clientRegistrationRepository);
	}
}
