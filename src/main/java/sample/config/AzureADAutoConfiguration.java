package sample.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@ConditionalOnProperty(prefix = "azure.activedirectory", name = "tenant-id")
@EnableConfigurationProperties(AzureADConfig.class)
public class AzureADAutoConfiguration {
    private static final SimpleGrantedAuthority DEFAULT_AUTH = new SimpleGrantedAuthority("ROLE_USER");
    private static final String DEFAULE_ROLE_PREFIX = "ROLE_";

    @Autowired
    private AzureADConfig azureADConfig;

    @Bean
    @ConditionalOnProperty(prefix = "azure.activedirectory.group", name = "enabled")
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        return this.delegationOidcUserService();
    }

    private OAuth2UserService<OidcUserRequest, OidcUser> delegationOidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            // Delegate to the default implementation for loading a user
            OidcUser oidcUser = delegate.loadUser(userRequest);

            OidcIdToken idToken = userRequest.getIdToken();

            String clientId = userRequest.getClientRegistration().getClientId();
            String clientSecret = userRequest.getClientRegistration().getClientSecret();
            String graphApiToken;

            try {
                // https://github.com/MicrosoftDocs/azure-docs/issues/8121#issuecomment-387090099
                // In AAD App Registration configure oauth2AllowImplicitFlow to true
                graphApiToken = AzureADGraphClient.acquireTokenForGraphApi(azureADConfig,
                        idToken.getTokenValue().toString(), clientId, clientSecret).getAccessToken();
            } catch (Exception e) {
                throw new IllegalStateException("Failed to acquire token for Graph API.", e);
            }


            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            // 1) Fetch the authority information from the protected resource using accessToken
            List<UserGroup> groups = AzureADGraphClient.getGroups(graphApiToken, azureADConfig.getAadMemberUrl());

            // 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities
            mappedAuthorities = groups.stream()
                    .filter(group -> azureADConfig.getGroup().getIncluded().contains(group.getDisplayName()))
                    .map(userGroup -> new SimpleGrantedAuthority(DEFAULE_ROLE_PREFIX + userGroup.getDisplayName()))
                    .collect(Collectors.toCollection(LinkedHashSet::new));

            // 3) Create a copy of oidcUser but use the mappedAuthorities instead
            if (mappedAuthorities.isEmpty()) {
                mappedAuthorities.add(DEFAULT_AUTH);
            }
            oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

            return oidcUser;
        };
    }
}
