package swiss.dasch.plugins.serviceusers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.jenkinsci.Symbol;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.security.SecurityRealm;
import jenkins.security.LastGrantedAuthoritiesProperty;
import jenkins.security.SecurityListener;

public class ServiceUserAuthoritiesProperty extends LastGrantedAuthoritiesProperty {

	private volatile String[] roles;

	public ServiceUserAuthoritiesProperty(List<String> roles) {
		this.roles = roles.toArray(new String[0]);
	}

	public List<String> getRoles() {
		return Collections.unmodifiableList(Arrays.asList(this.roles));
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities2() {
		// Re-implementing LastGrantedAuthoritiesProperty#getAuthorities2() because we
		// shadow the "roles" field

		String[] roles = this.roles; // capture to a variable for immutability

		if (roles == null) {
			return Collections.singleton(SecurityRealm.AUTHENTICATED_AUTHORITY2);
		}

		String authenticatedRole = SecurityRealm.AUTHENTICATED_AUTHORITY2.getAuthority();
		List<GrantedAuthority> grantedAuthorities = new ArrayList<>(roles.length + 1);
		grantedAuthorities.add(new SimpleGrantedAuthority(authenticatedRole));

		for (String role : roles) {
			// to avoid having twice that role
			if (!authenticatedRole.equals(role)) {
				grantedAuthorities.add(new SimpleGrantedAuthority(role));
			}
		}

		return grantedAuthorities;
	}

	@SuppressWarnings("deprecation")
	@Override
	public org.acegisecurity.GrantedAuthority[] getAuthorities() {
		return org.acegisecurity.GrantedAuthority.fromSpring(this.getAuthorities2());
	}

	@Override
	public void update(Authentication auth) throws IOException {
		// NO-OP
	}

	@Override
	public void invalidate() throws IOException {
		// NO-OP
	}

	@Extension(ordinal = -Double.MAX_VALUE /* Run after LastGrantedAuthoritiesProperty.SecurityListenerImpl */)
	public static class LoginListener extends SecurityListener {

		@Override
		protected void loggedIn(String username) {
			User user = User.getById(username, false);

			if (user != null) {
				ServiceUserProperty property = user.getProperty(ServiceUserProperty.class);

				if (property != null) {
					property.applyRoles();
				}
			}
		}

	}

	@Extension
	@Symbol("serviceUserAuthorities")
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
			return Messages.ServiceUserAuthoritiesProperty_DisplayName();
		}

	}

}
