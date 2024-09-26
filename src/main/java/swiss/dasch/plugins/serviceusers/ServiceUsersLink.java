package swiss.dasch.plugins.serviceusers;

import hudson.Extension;
import hudson.model.ManagementLink;
import hudson.security.Permission;
import jenkins.model.Jenkins;

@Extension
public class ServiceUsersLink extends ManagementLink {

	@Override
	public String getDisplayName() {
		return Messages.ServiceUsersLink_DisplayName();
	}

	@Override
	public String getIconFileName() {
		if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
			return null;
		}
		return "symbol-hammer";
	}

	@Override
	public String getUrlName() {
		if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
			return null;
		}
		return ServiceUsers.get().getUrlName();
	}

	@Override
	public Category getCategory() {
		return Category.SECURITY;
	}

	@Override
	public Permission getRequiredPermission() {
		return Jenkins.ADMINISTER;
	}

}
