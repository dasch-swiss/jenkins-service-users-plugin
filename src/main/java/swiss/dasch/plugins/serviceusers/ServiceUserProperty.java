package swiss.dasch.plugins.serviceusers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.Nullable;

import org.jenkinsci.Symbol;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import jenkins.security.ApiTokenProperty;

/**
 * Simply a marker to identify a user as service user
 */
public class ServiceUserProperty extends UserProperty {

	private static final Logger LOGGER = Logger.getLogger(ServiceUsers.class.getName());

	private List<String> roles;

	private Map<String, String> tokenUuidMap;

	public boolean setRoles(List<String> roles) {
		this.roles = new ArrayList<>(roles);
		return this.applyRoles();
	}

	public List<String> getRoles() {
		List<String> roles = this.roles;
		return roles == null ? Collections.emptyList() : Collections.unmodifiableList(roles);
	}

	public boolean applyRoles() {
		if (this.user != null) {
			try {
				List<String> newRoles = this.getRoles();

				ServiceUserAuthoritiesProperty p = this.user.getProperty(ServiceUserAuthoritiesProperty.class);

				if (p == null || !p.getRoles().equals(newRoles)) {
					this.user.addProperty(new ServiceUserAuthoritiesProperty(newRoles));
					this.user.save();
				}

				return true;
			} catch (IOException ex) {
				LOGGER.log(Level.SEVERE, "Failed to add granted authorities to service user", ex);
			}
		}

		return false;
	}

	public boolean setApiToken(String name, @Nullable String token) {
		if (this.user != null) {
			ApiTokenProperty property = this.user.getProperty(ApiTokenProperty.class);

			if (property == null) {
				return false;
			}

			String uuid = this.tokenUuidMap != null ? this.tokenUuidMap.get(name) : null;

			try {
				boolean changed = false;

				// Token may be different so old one must always be revoked
				if (uuid != null) {
					property.revokeToken(uuid);

					if (this.tokenUuidMap != null) {
						this.tokenUuidMap.remove(name);
					}

					changed = true;
				}

				if (token != null) {
					uuid = property.addFixedNewToken(name, token);

					synchronized (this) {
						if (this.tokenUuidMap == null) {
							this.tokenUuidMap = new HashMap<>();
						}
					}

					this.tokenUuidMap.put(name, uuid);

					changed = true;
				}

				if (changed) {
					this.user.save();
				}

				return true;
			} catch (IOException ex) {
				LOGGER.log(Level.SEVERE, "Failed to update api token of service user", ex);
			}
		}

		return false;
	}

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
