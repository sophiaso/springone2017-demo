package sample.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.validation.constraints.NotEmpty;

@ConfigurationProperties(prefix = "azure.activedirectory")
public class AzureADConfig {
    private String graphAPIUrl;

    private String aadSiginUrl;

    private String aadMemberUrl;

    @NotEmpty
    private String tenantId;

    public String getGraphAPIUrl() {
        return graphAPIUrl;
    }

    public void setGraphAPIUrl(String graphAPIUrl) {
        this.graphAPIUrl = graphAPIUrl;
    }

    public String getAadSiginUrl() {
        return aadSiginUrl;
    }

    public void setAadSiginUrl(String aadSiginUrl) {
        this.aadSiginUrl = aadSiginUrl;
    }

    public String getAadMemberUrl() {
        return aadMemberUrl;
    }

    public void setAadMemberUrl(String aadMemberUrl) {
        this.aadMemberUrl = aadMemberUrl;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

}
