package sample.config;

import org.junit.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;

import static org.assertj.core.api.Assertions.assertThat;

public class AutoConfigurationTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AzureADAutoConfiguration.class));

    @Test
    public void testOAuth2UserServiceBeanExists() {
        this.contextRunner
                .withPropertyValues("azure.activedirectory.group.enabled=true",
                        "azure.activedirectory.tenant-id=my-tenant-id")
                .run((context) -> {
                    assertThat(context).hasSingleBean(OAuth2UserService.class);
                });
    }

    @Test
    public void testAADGroupNotEnabled() {
        this.contextRunner
                .withPropertyValues("azure.activedirectory.group.enabled=false",
                        "azure.activedirectory.tenant-id=my-tenant-id")
                .run((context) -> {
                    assertThat(context).doesNotHaveBean(OAuth2UserService.class);
                });
    }

    @Test
    public void testAADAutoConfigureNotTriggered() {
        this.contextRunner
                .withPropertyValues("azure.activedirectory.group.enabled=true")
                .run((context) -> {
                    assertThat(context).doesNotHaveBean(OAuth2UserService.class);
                });
    }
}
