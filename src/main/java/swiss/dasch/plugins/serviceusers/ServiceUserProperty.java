package swiss.dasch.plugins.serviceusers;

import org.jenkinsci.Symbol;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;

/**
 * Simply a marker to identify a user as service user
 */
public class ServiceUserProperty extends UserProperty {

	@Extension
	@Symbol("isServiceUser")
	public static final class DescriptorImpl extends UserPropertyDescriptor {

		@Override
		public UserProperty newInstance(User user) {
			return null;
		}

		@Override
		public boolean isEnabled() {
			return false;
		}

		@Override
		public String getDisplayName() {
			return Messages.ServiceUserProperty_DisplayName();
		}

	}

}
