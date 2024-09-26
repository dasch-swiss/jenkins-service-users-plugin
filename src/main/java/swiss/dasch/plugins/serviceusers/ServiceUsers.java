package swiss.dasch.plugins.serviceusers;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.PatternSyntaxException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.verb.POST;

import hudson.Extension;
import hudson.Util;
import hudson.model.RootAction;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;

@Symbol("serviceUsers")
@Extension
public class ServiceUsers extends GlobalConfiguration implements RootAction {

	private static final Logger LOGGER = Logger.getLogger(ServiceUsers.class.getName());

	private static final SecureRandom RANDOM = new SecureRandom();

	private Set<String> serviceUsers = new LinkedHashSet<>();

	public ServiceUsers() {
		this.load();
		this.createOrUpdateAllUsers();
	}

	@DataBoundSetter
	public synchronized void setUsers(List<String> users) {
		Set<String> prevUsers = new LinkedHashSet<>(this.serviceUsers);

		Set<String> newUsers = new LinkedHashSet<>(users);

		for (String prevUser : prevUsers) {
			if (!newUsers.contains(prevUser)) {
				this.removeUser(prevUser);
			}
		}

		this.addUsers(newUsers);
	}

	public List<String> getUsers() {
		return Collections.unmodifiableList(new ArrayList<>(this.serviceUsers));
	}

	public boolean addUser(String user) {
		return this.addUsers(Collections.singletonList(user));
	}

	public synchronized boolean addUsers(Collection<String> users) {
		boolean added = false;

		for (String user : users) {
			if (this.serviceUsers.add(user)) {
				boolean success = false;

				try {
					success = this.createOrUpdateUser(user);
				} finally {
					if (!success) {
						this.serviceUsers.remove(user);
					}
				}

				this.save();

				added = true;
			}
		}

		return added;
	}

	public boolean removeUser(String user) {
		return this.removeUsers(Collections.singletonList(user));
	}

	public synchronized boolean removeUsers(Collection<String> users) {
		boolean changed = false;

		for (String user : users) {
			if (this.serviceUsers.remove(user)) {
				User u = User.getById(user, false);

				if (u != null && u.getProperty(ServiceUserProperty.class) != null) {
					try {
						u.delete();
					} catch (IOException e) {
						LOGGER.log(Level.WARNING, "Failed removing service user  " + user, e);
					}
				}

				changed = true;
			}
		}

		if (changed) {
			this.save();
			return true;
		}

		return false;
	}

	public boolean removeUsersByPattern(String pattern) {
		return this.removeUsersByPattern(pattern, Collections.emptyList());
	}

	public synchronized boolean removeUsersByPattern(String pattern, Collection<String> except) {
		Set<String> exceptSet = new HashSet<>(except);

		List<String> remove = new ArrayList<>();

		for (String user : this.getUsers()) {
			try {
				if (!exceptSet.contains(user) && user.matches(pattern)) {
					remove.add(user);
				}
			} catch (PatternSyntaxException ex) {
				// Ignore
			}
		}

		return this.removeUsers(remove);
	}

	private synchronized void createOrUpdateAllUsers() {
		SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
		for (String user : this.serviceUsers) {
			this.createOrUpdateUser(user, securityRealm);
		}
	}

	private boolean createOrUpdateUser(String userId) {
		return this.createOrUpdateUser(userId, Jenkins.get().getSecurityRealm());
	}

	private boolean createOrUpdateUser(String userId, SecurityRealm securityRealm) {
		this.checkExistingUser(userId);

		User user = null;

		// The built-in security realm requires a password for impersonation
		// to work so a random 32 char password is generated.
		if (securityRealm instanceof HudsonPrivateSecurityRealm) {
			HudsonPrivateSecurityRealm builtinSecurityRealm = (HudsonPrivateSecurityRealm) securityRealm;

			byte[] random = new byte[16];
			RANDOM.nextBytes(random);

			String password = Util.toHexString(random);
			assert password.length() == 32;

			try {
				user = builtinSecurityRealm.createAccount(userId, password);
			} catch (IOException e) {
				LOGGER.log(Level.WARNING, "Failed creating service user " + userId + " account", e);
			}
		}

		if (user == null) {
			// For other security realms just create the user as-is.
			// Whether the service user can actually be impersonated is
			// in the end up to the security realm.
			// This creates the user if it doesn't exist yet.
			user = User.getById(userId, true);
		}

		if (user != null) {
			try {
				user.addProperty(new ServiceUserProperty());
				return true;
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, "Failed adding service user property to " + userId, e);
			}
		}

		return false;
	}

	private void checkExistingUser(String userId) {
		User user = User.getById(userId, false);

		if (user != null && user.getProperty(ServiceUserProperty.class) == null) {
			throw new UserAlreadyExistsException(
					"Cannot create service user " + userId + " because another user with the same ID already exists",
					userId);
		}
	}

	public static class FormData {
		public final String user;

		@DataBoundConstructor
		public FormData(String user) {
			this.user = Util.fixEmptyAndTrim(user);
		}
	}

	@POST
	public void doAddUser(StaplerRequest req, StaplerResponse resp) throws IOException, ServletException {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);

		FormData data = req.bindJSON(FormData.class, req.getSubmittedForm());

		if (data.user != null) {
			try {
				this.addUser(data.user);
			} catch (UserAlreadyExistsException e) {
				resp.sendError(HttpServletResponse.SC_CONFLICT, "User already exists");
				return;
			}
		}

		resp.forwardToPreviousPage(req);
	}

	@POST
	public void doRemoveUser(StaplerRequest req, StaplerResponse resp) throws IOException, ServletException {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);

		FormData data = req.bindJSON(FormData.class, req.getSubmittedForm());

		if (data.user != null) {
			this.removeUser(data.user);
		}

		resp.forwardToPreviousPage(req);
	}

	@Override
	public String getIconFileName() {
		return null;
	}

	@Override
	public String getUrlName() {
		return "serviceUsers";
	}

	@Override
	public String getDisplayName() {
		return Messages.ServiceUsers_DisplayName();
	}

	public static ServiceUsers get() {
		return (ServiceUsers) Jenkins.get().getDescriptorOrDie(ServiceUsers.class);
	}

}
