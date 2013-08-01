/*
 * (C) Copyright 2013 Nuxeo SA (http://nuxeo.com/) and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 * 	   sleroux
 *     Christophe Capon <christophe.capon@vilogia.fr>
 */

package org.nuxeo.ecm.ui.web.auth.cookie;

import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.LOGIN_ERROR;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPluginLogoutExtension;
import org.nuxeo.ecm.platform.ui.web.auth.plugins.FormAuthenticator;

/**
 * Classe qui etend le FormAuthenticator fourni par Nuxeo pour y ajouter la
 * gestion du login persistent ("remember me") via l'utilisation d'un cookie.
 * 
 * @author sleroux
 * @author <a href="mailto:christophe.capon@vilogia.fr">Christophe Capon</a>
 */

public class CookieFormAuthenticator extends FormAuthenticator implements
		NuxeoAuthenticationPluginLogoutExtension {

	/**
	 * The logger.
	 */
	private static final Log LOG = LogFactory
			.getLog(CookieFormAuthenticator.class);

	/**
	 * The "Remember me" checkbox name in the login form.
	 */
	protected String remembermeKey = "remember_me";

	/**
	 * The auth cookie name.
	 */
	protected String authCookieName = "auth_cookie_name";

	/**
	 * The auth cookie duration.
	 */
	protected int authCookieDuration = -1;

	/**
	 * If true, the cookie duration is refresh each time the user use Nuxeo.
	 */
	protected boolean authCookieDurationRefresh = false;

	/**
	 * The value encoding of the auth cookie.
	 */
	protected String authCookieEncoding = "UTF-8";

	/**
	 * Token manager
	 */
	protected TokenManager mgr = null;

	/**
	 * Find the auth cookie in the request.
	 * 
	 * @param pHttpRequest
	 *            the request
	 * @return the cookie or null if the auth cookie is not found
	 */
	protected Cookie getAuthCookie(final HttpServletRequest pHttpRequest) {
		Cookie[] cookies = pHttpRequest.getCookies();
		if (cookies != null) {
			for (int i = 0; i < cookies.length; i++) {
				if (authCookieName.equals(cookies[i].getName())) {
					if ((cookies[i].getValue() != null)
							&& (!"".equals(cookies[i].getValue()))) {
						return cookies[i];
					}
				}
			}
		}
		return null;
	}

	/**
	 * Create the auth cookie in the response.
	 * 
	 * @param pUserIdentificationInfo
	 *            the cookie value
	 * @param pHttpRequest
	 *            the request
	 * @param pHttpResponse
	 *            the response
	 */
	protected void createAuthCookie(
			final UserIdentificationInfo pUserIdentificationInfo,
			final HttpServletRequest pHttpRequest,
			final HttpServletResponse pHttpResponse) {
		LOG.debug("Create auth cookie");

		try {
			String token = getTokenManager().saveAuthInfo(
					pUserIdentificationInfo);
			String cookieValue = URLEncoder.encode(token, authCookieEncoding);
			Cookie authCookie = getAuthCookie(pHttpRequest);
			if (authCookie != null) {
				// Update an existing cookie
				authCookie.setValue(cookieValue);
			} else {
				// Make a new cookie
				authCookie = new Cookie(authCookieName, cookieValue);
			}
			authCookie.setMaxAge(authCookieDuration);
			pHttpResponse.addCookie(authCookie);

		} catch (UnsupportedEncodingException e) {
			LOG.error("Auth cookie encoding is not supported: "
					+ authCookieEncoding, e);
		}
	}

	/**
	 * Update the age of the auth cookie in the response.
	 * 
	 * @param pHttpRequest
	 *            the request
	 * @param pHttpResponse
	 *            the response
	 */
	protected void updateAuthCookieAge(final HttpServletRequest pHttpRequest,
			final HttpServletResponse pHttpResponse) {
		Cookie authCookie = getAuthCookie(pHttpRequest);
		if (authCookie != null) {
			authCookie.setMaxAge(authCookieDuration);
			pHttpResponse.addCookie(authCookie);
			LOG.debug("Update auth cookie age");
		} else {
			LOG.debug("No auth cookie to update");
		}
	}

	/**
	 * Find the auth cookie in the request and return its value, if the cookie
	 * is found.
	 * 
	 * @param pHttpRequest
	 *            the request
	 * @return the value or null if the auth cookie is not found
	 */
	protected UserIdentificationInfo getAuthCookieValue(
			final HttpServletRequest pHttpRequest) {
		Cookie authCookie = getAuthCookie(pHttpRequest);
		if (authCookie != null) {
			try {
				String token = (String) URLDecoder.decode(
						authCookie.getValue(), authCookieEncoding);
				UserIdentificationInfo userIdentificationInfo = getTokenManager()
						.getAuthInfo(token);
				LOG.debug("Read auth cookie value");
				return userIdentificationInfo;
			} catch (UnsupportedEncodingException e) {
				LOG.error("Auth cookie decoding is not supported: "
						+ authCookieEncoding, e);
			}
		} else {
			LOG.debug("No auth cookie to read");
		}
		return null;
	}

	/**
	 * Delete the auth cookie in the response.
	 * 
	 * @param pHttpRequest
	 *            the request
	 * @param pHttpResponse
	 *            the response
	 */
	protected void deleteAuthCookie(final HttpServletRequest pHttpRequest,
			final HttpServletResponse pHttpResponse) {
		Cookie authCookie = getAuthCookie(pHttpRequest);
		if (authCookie != null) {
			try {

				String token = (String) URLDecoder.decode(
						authCookie.getValue(), authCookieEncoding);
				getTokenManager().removeAuthInfo(token);
				
				LOG.debug("Delete auth cookie");
				authCookie.setValue("");
				authCookie.setMaxAge(0);
				pHttpResponse.addCookie(authCookie);
			} catch (UnsupportedEncodingException e) {
				LOG.error("Auth cookie decoding is not supported: "
						+ authCookieEncoding, e);
			}
		} else {
			LOG.debug("No auth cookie to delete");
		}
	}

	/**
	 * Handles the Login Prompt.
	 * 
	 * @param pHttpRequest
	 *            the request
	 * @param pHttpResponse
	 *            the response
	 * @param pBaseURL
	 *            the base url
	 * @return true if AuthFilter must stop execution (ie: login prompt
	 *         generated a redirect), false otherwise
	 */
	public Boolean handleLoginPrompt(final HttpServletRequest pHttpRequest,
			final HttpServletResponse pHttpResponse, final String pBaseURL) {
		Boolean result = super.handleLoginPrompt(pHttpRequest, pHttpResponse,
				pBaseURL);

		LOG.debug("Handles the Login Prompt for [" + pBaseURL + "]: " + result);
		return result;
	}

	/**
	 * Retrieves user identification information from the request.
	 * 
	 * @param pHttpRequest
	 *            the request
	 * @param pHttpResponse
	 *            the response
	 * @return UserIdentificationInfo
	 */
	public UserIdentificationInfo handleRetrieveIdentity(
			final HttpServletRequest pHttpRequest,
			final HttpServletResponse pHttpResponse) {

		UserIdentificationInfo userIdentificationInfo = super
				.handleRetrieveIdentity(pHttpRequest, pHttpResponse);
		boolean rememberMe = "true".equals(pHttpRequest
				.getParameter(remembermeKey));

		LOG.debug("Retrieves user identification information from the request: ("
				+ usernameKey
				+ "="
				+ ((userIdentificationInfo != null) ? userIdentificationInfo
						.getUserName() : "null")
				+ ","
				+ remembermeKey
				+ "="
				+ rememberMe + ")");

		if (userIdentificationInfo != null) {
			if (rememberMe) {
				createAuthCookie(userIdentificationInfo, pHttpRequest,
						pHttpResponse);
			} else {
				deleteAuthCookie(pHttpRequest, pHttpResponse);
			}
		} else {
			userIdentificationInfo = getAuthCookieValue(pHttpRequest);
			if (userIdentificationInfo != null) {
				LOG.debug("Retrieves user identification information from the auth cookie: ("
						+ usernameKey
						+ "="
						+ userIdentificationInfo.getUserName() + ")");
				pHttpRequest.removeAttribute(LOGIN_ERROR);

				if (authCookieDurationRefresh) {
					// Update max age cookie
					updateAuthCookieAge(pHttpRequest, pHttpResponse);
				}
			}
		}
		return userIdentificationInfo;
	}

	/**
	 * Defines if the authentication plugin needs to do a login prompt.
	 * 
	 * @param pHttpRequest
	 *            the request
	 * @return true if LoginPrompt is used
	 */
	public Boolean needLoginPrompt(final HttpServletRequest pHttpRequest) {
		Boolean result = new Boolean(getAuthCookieValue(pHttpRequest) == null);
		LOG.debug("The authentication plugin needs to do a login prompt: "
				+ result);
		return result;
	}

	/**
	 * Initializes the Plugin from parameters set in the XML descriptor.
	 * 
	 * @param pParameters
	 *            the parameters
	 */
	public void initPlugin(final Map<String, String> pParameters) {
		LOG.debug("");
		LOG.debug("");
		LOG.debug("Init ImaFormAuthenticator plugin with parameters: "
				+ pParameters);
		super.initPlugin(pParameters);

		if (pParameters.get("RemembermeKey") != null) {
			remembermeKey = pParameters.get("RemembermeKey");
		}
		if (pParameters.get("AuthCookieName") != null) {
			authCookieName = pParameters.get("AuthCookieName");
		}
		if (pParameters.get("AuthCookieDuration") != null) {
			authCookieDuration = new Integer(
					pParameters.get("AuthCookieDuration")).intValue() * 24 * 60 * 60;
		}
		if (pParameters.get("AuthCookieDurationRefresh") != null) {
			authCookieDurationRefresh = new Boolean(
					pParameters.get("AuthCookieDurationRefresh"))
					.booleanValue();
		}
	}

	/**
	 * Returns the list of prefix for unauthenticated URLs, typically the URLs
	 * associated to login prompt.
	 * 
	 * @return the list of prefix
	 */
	public List<String> getUnAuthenticatedURLPrefix() {
		List<String> result = super.getUnAuthenticatedURLPrefix();

		LOG.debug("Return the list of prefix for unauthenticated URLs: "
				+ result);
		return result;
	}

	/**
	 * Handles logout operation.
	 * <p>
	 * Generic logout (killing session and Seam objects) is done by
	 * LogoutActionBean This interface must be implemented by auth plugin when
	 * the target auth system needs a specific logout procedure.
	 * 
	 * @param pHttpRequest
	 *            the request
	 * @param pHttpResponse
	 *            the response
	 * @return true if caller must stop execution (ie: logout generated a
	 *         redirect), false otherwise
	 */
	public Boolean handleLogout(final HttpServletRequest pHttpRequest,
			final HttpServletResponse pHttpResponse) {
		LOG.debug("Handles logout operation");
		deleteAuthCookie(pHttpRequest, pHttpResponse);
		return Boolean.FALSE;
	}

	/**
	 * Lazy instanciation of the token manager
	 * 
	 * @return the token manager
	 */
	private TokenManager getTokenManager() {
		if (mgr == null)
			mgr = new TokenManager();
		return mgr;
	}
}
