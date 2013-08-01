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
 *     Christophe Capon <christophe.capon@vilogia.fr>
 */

package org.nuxeo.ecm.ui.web.auth.cookie;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.connect.identity.Base64;
import org.nuxeo.ecm.directory.DirectoryException;
import org.nuxeo.ecm.directory.api.DirectoryService;
import org.nuxeo.ecm.directory.sql.SQLDirectory;
import org.nuxeo.ecm.directory.sql.SQLDirectoryProxy;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.runtime.api.Framework;

/**
 * Ensures persistence of the user authentication information with a SQLDirectory.
 * 
 * @author <a href="mailto:christophe.capon@vilogia.fr">Christophe Capon</a>
 * 
 */
/**
 * @author Christophe Capon <christophe.capon@vilogia.fr>
 * 
 */
public class TokenManager {

	private static final Log LOG = LogFactory.getLog(TokenManager.class);

	
	private SQLDirectory dir;
	private Connection connection;
	private PreparedStatement insert;
	private PreparedStatement delete;
	private PreparedStatement select;

	/**
	 * Constructor. Initializes database connetion and prepares SQL statements.
	 */
	public TokenManager() {

		try {
			
			DirectoryService service = Framework.getService(DirectoryService.class);

			dir = ((SQLDirectoryProxy) service.getDirectory("cookieAuths"))
					.getDirectory();
			connection = dir.getConnection();
			select = connection
					.prepareStatement("select authinfo from cookie_auth where token = ?");
			insert = connection
					.prepareStatement("insert into cookie_auth (token, username, authinfo) values(?, ?, ?)");
			delete = connection
					.prepareStatement("delete from cookie_auth where token = ?");
		} catch (DirectoryException e) {
			LOG.error("Unable to get directory or connection to the database",
					e);
		} catch (SQLException e) {
			LOG.error("Unable to initialize statements", e);
		} catch (Exception e) {
			LOG.error("Unable to get directory service", e);
		}
	}

	/**
	 * Saves to the user identification information to database.
	 * @param userIdentificationInfo object to save
	 * @return the generated token. It is an randomly generated UUID.
	 */
	String saveAuthInfo(UserIdentificationInfo userIdentificationInfo) {

		String token = UUID.randomUUID().toString();

		try {
			// Securely remove previous version
			removeAuthInfo(token);
			
			insert.setString(1, token);
			insert.setString(2, userIdentificationInfo.getUserName());
			insert.setString(3, Base64.encodeObject(userIdentificationInfo));
			
			insert.executeUpdate();
			
		} catch (SQLException e) {
			LOG.error("Error while saving auth info", e);
		}

		// even if error, return the token. Does not matter: when the user comes back, the token will not be found
		// in the database and user will fallback on login screen.
		return token;
	}

	/**
	 * Removes the autentication information. Invoked when a new token is created or when the
	 * user explicitly logs out. 
	 * @param token Token to remove
	 */
	void removeAuthInfo(String token) {
		try {
			delete.setString(1, token);
			delete.executeUpdate();
		} catch (SQLException e) {
			LOG.error("Error while deleting auth info", e);
		}
	}

	/**
	 * Loads the user authentication from token. 
	 * @param token sent by the navigator from a cookie
	 * @return user identification information or null if not found
	 */
	UserIdentificationInfo getAuthInfo(String token) {

		try {
			select.setString(1, token);
			ResultSet rs = select.executeQuery();
			if (rs.next()) {
				UserIdentificationInfo info = (UserIdentificationInfo) Base64
						.decodeToObject(rs.getString("authinfo"));
				return info;
			}
			return null;
		} catch (SQLException e) {
			LOG.error("Error while getting identifiaction info");
			return null;
		}

	}

}
