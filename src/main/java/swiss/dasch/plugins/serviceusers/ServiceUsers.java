package swiss.dasch.plugins.serviceusers;

import java.util.Collection;
import java.util.List;

import javax.annotation.Nullable;

import org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists.Whitelisted;

import jenkins.model.Jenkins;

public class ServiceUsers {

	private static final ServiceUsers INSTANCE = new ServiceUsers();

	private ServiceUsers() {
	}

	@Whitelisted(restricted = true)
	public static ServiceUsers get() {
		return INSTANCE;
	}

	@Whitelisted(restricted = true)
	public List<String> getUsers() {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);
		return ServiceUsersConfig.get().getUsers();
	}

	@Whitelisted(restricted = true)
	public boolean addUser(String user) {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);
		return ServiceUsersConfig.get().addUser(user);
	}

	@Whitelisted(restricted = true)
	public boolean addUsers(Collection<String> users) {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);
		return ServiceUsersConfig.get().addUsers(users);
	}

	@Whitelisted(restricted = true)
	public boolean setGroups(String user, List<String> groups) {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);
		return ServiceUsersConfig.get().setGroups(user, groups);
	}

	@Whitelisted(restricted = true)
	public boolean setApiToken(String user, String name, @Nullable String token) {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);
		return ServiceUsersConfig.get().setApiToken(user, name, token);
	}

	@Whitelisted(restricted = true)
	public boolean removeUser(String user) {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);
		return ServiceUsersConfig.get().removeUser(user);
	}

	@Whitelisted(restricted = true)
	public boolean removeUsers(Collection<String> users) {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);
		return ServiceUsersConfig.get().removeUsers(users);
	}

	@Whitelisted(restricted = true)
	public boolean removeUsersByPattern(String pattern) {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);
		return ServiceUsersConfig.get().removeUsersByPattern(pattern);
	}

	@Whitelisted(restricted = true)
	public boolean removeUsersByPattern(String pattern, Collection<String> except) {
		Jenkins.get().checkPermission(Jenkins.ADMINISTER);
		return ServiceUsersConfig.get().removeUsersByPattern(pattern, except);
	}

}
