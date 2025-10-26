package swiss.dasch.plugins.serviceusers;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import hudson.Extension;
import hudson.init.Initializer;
import hudson.model.User;
import hudson.util.PluginServletFilter;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jenkins.security.BasicHeaderApiTokenAuthenticator;

@Extension
public class AuthenticationFilter implements Filter {

	@Initializer
	public static void init() throws ServletException {
		PluginServletFilter.addFilter(new AuthenticationFilter());
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		// Only allow authenticating as service user via API token and not password

		if (!isAuthenticatedViaApiToken(request)) {
			denyServiceUserAuthentication();
		}

		chain.doFilter(request, response);

	}

	private static boolean isAuthenticatedViaApiToken(ServletRequest request) {
		return Boolean.TRUE.equals(request.getAttribute(BasicHeaderApiTokenAuthenticator.class.getName()));
	}

	private static void denyServiceUserAuthentication() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		if (auth != null) {
			String username = auth.getName();

			User user = User.getById(username, false);

			if (user != null && user.getProperty(ServiceUserProperty.class) != null) {
				SecurityContextHolder.clearContext();
				throw new AccessDeniedException("Cannot login as service user: " + username);
			}
		}
	}

	@Override
	public void destroy() {
	}

}
