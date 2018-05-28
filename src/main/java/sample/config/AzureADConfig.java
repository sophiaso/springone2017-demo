package sample.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.validation.constraints.NotEmpty;
import java.util.List;

@ConfigurationProperties(prefix = "azure.activedirectory")
public class AzureADConfig {
    private String graphAPIUrl;

    private String aadSiginUrl;

    private String aadMemberUrl;

    private String tenantId;

    private Group group;

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

    public Group getGroup() {
        return group;
    }

    public void setGroup(Group group) {
        this.group = group;
    }

    public static class Group {
        private boolean isEnabled;
        private List<String> included;

        public boolean isEnabled() {
            return isEnabled;
        }

        public void setEnabled(boolean enabled) {
            isEnabled = enabled;
        }

        public List<String> getIncluded() {
            return included;
        }

        public void setIncluded(List<String> included) {
            this.included = included;
        }
    }

}
