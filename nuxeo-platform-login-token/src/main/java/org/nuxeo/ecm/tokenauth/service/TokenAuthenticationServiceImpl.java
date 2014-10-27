/*
 * (C) Copyright 2006-20012 Nuxeo SA (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *     Antoine Taillefer
 */
package org.nuxeo.ecm.tokenauth.service;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.ClientRuntimeException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;
import org.nuxeo.ecm.directory.BaseSession;
import org.nuxeo.ecm.directory.Session;
import org.nuxeo.ecm.directory.api.DirectoryService;
import org.nuxeo.ecm.tokenauth.TokenAuthenticationException;
import org.nuxeo.runtime.api.Framework;

/**
 * Default implementation of the {@link TokenAuthenticationService}.
 * <p>
 * The token is generated by the {@link UUID#randomUUID()} method which
 * guarantees its uniqueness. The storage back-end is a SQL Directory.
 *
 * @author Antoine Taillefer (ataillefer@nuxeo.com)
 * @since 5.7
 */
public class TokenAuthenticationServiceImpl implements
        TokenAuthenticationService {

    private static final long serialVersionUID = 35041039370298705L;

    private static final Log log = LogFactory.getLog(TokenAuthenticationServiceImpl.class);

    protected static final String DIRECTORY_NAME = "authTokens";

    protected static final String DIRECTORY_SCHEMA = "authtoken";

    protected static final String USERNAME_FIELD = "userName";

    protected static final String TOKEN_FIELD = "token";

    protected static final String APPLICATION_NAME_FIELD = "applicationName";

    protected static final String DEVICE_ID_FIELD = "deviceId";

    protected static final String DEVICE_DESCRIPTION_FIELD = "deviceDescription";

    protected static final String PERMISSION_FIELD = "permission";

    protected static final String CREATION_DATE_FIELD = "creationDate";

    @Override
    public String acquireToken(String userName, String applicationName,
            String deviceId, String deviceDescription, String permission)
            throws TokenAuthenticationException {

        // Look for a token bound to the (userName,
        // applicationName, deviceId) triplet, if it exists return it,
        // else generate a unique one
        String token = getToken(userName, applicationName, deviceId);
        if (token != null) {
            return token;
        }

        // Check required parameters (userName, applicationName and deviceId are
        // already checked in #getToken)
        if (StringUtils.isEmpty(permission)) {
            throw new TokenAuthenticationException(
                    "The permission parameter is mandatory to acquire an authentication token.");
        }

        // Log in as system user
        LoginContext lc;
        try {
            lc = Framework.login();
        } catch (LoginException e) {
            throw new ClientException("Cannot log in as system user", e);
        }
        try {
            // Open directory session
            final Session session = Framework.getService(DirectoryService.class).open(
                    DIRECTORY_NAME);
            try {
                // Generate random token, store the binding and return the token
                UUID uuid = UUID.randomUUID();
                token = uuid.toString();

                final DocumentModel entry = getBareAuthTokenModel(Framework.getService(DirectoryService.class));
                entry.setProperty(DIRECTORY_SCHEMA, TOKEN_FIELD, token);
                entry.setProperty(DIRECTORY_SCHEMA, USERNAME_FIELD, userName);
                entry.setProperty(DIRECTORY_SCHEMA, APPLICATION_NAME_FIELD,
                        applicationName);
                entry.setProperty(DIRECTORY_SCHEMA, DEVICE_ID_FIELD, deviceId);
                if (!StringUtils.isEmpty(deviceDescription)) {
                    entry.setProperty(DIRECTORY_SCHEMA,
                            DEVICE_DESCRIPTION_FIELD, deviceDescription);
                }
                entry.setProperty(DIRECTORY_SCHEMA, PERMISSION_FIELD,
                        permission);
                Calendar creationDate = Calendar.getInstance();
                creationDate.setTimeInMillis(System.currentTimeMillis());
                entry.setProperty(DIRECTORY_SCHEMA, CREATION_DATE_FIELD,
                        creationDate);
                session.createEntry(entry);

                log.debug(String.format(
                        "Generated unique token for the (userName, applicationName, deviceId) triplet: ('%s', '%s', '%s'), returning it.",
                        userName, applicationName, deviceId));
                return token;

            } finally {
                session.close();
            }
        } finally {
            try {
                // Login context may be null in tests
                if (lc != null) {
                    lc.logout();
                }
            } catch (LoginException e) {
                throw new ClientException("Cannot log out system user", e);
            }
        }
    }

    @Override
    public String getToken(String userName, String applicationName,
            String deviceId) throws TokenAuthenticationException {

        if (StringUtils.isEmpty(userName)
                || StringUtils.isEmpty(applicationName)
                || StringUtils.isEmpty(deviceId)) {
            throw new TokenAuthenticationException(
                    "The following parameters are mandatory to get an authentication token: userName, applicationName, deviceId.");
        }

        // Log in as system user
        LoginContext lc;
        try {
            lc = Framework.login();
        } catch (LoginException e) {
            throw new ClientException("Cannot log in as system user", e);
        }
        try {
            // Open directory session
            final Session session = Framework.getService(DirectoryService.class).open(
                    DIRECTORY_NAME);
            try {
                // Look for a token bound to the (userName,
                // applicationName, deviceId) triplet, if it exists return it,
                // else return null
                final Map<String, Serializable> filter = new HashMap<String, Serializable>();
                filter.put(USERNAME_FIELD, userName);
                filter.put(APPLICATION_NAME_FIELD, applicationName);
                filter.put(DEVICE_ID_FIELD, deviceId);
                DocumentModelList tokens = session.query(filter);
                if (!tokens.isEmpty()) {
                    // Multiple tokens found for the same triplet, this is
                    // inconsistent
                    if (tokens.size() > 1) {
                        throw new ClientRuntimeException(
                                String.format(
                                        "Found multiple tokens for the (userName, applicationName, deviceId) triplet: ('%s', '%s', '%s'), this is inconsistent.",
                                        userName, applicationName, deviceId));
                    }
                    // Return token
                    log.debug(String.format(
                            "Found token for the (userName, applicationName, deviceId) triplet: ('%s', '%s', '%s'), returning it.",
                            userName, applicationName, deviceId));
                    DocumentModel tokenModel = tokens.get(0);
                    return tokenModel.getId();
                }

                log.debug(String.format(
                        "No token found for the (userName, applicationName, deviceId) triplet: ('%s', '%s', '%s'), returning null.",
                        userName, applicationName, deviceId));
                return null;

            } catch (ClientException e) {
                log.error(e);
                throw e;
            } finally {
                session.close();
            }
        } finally {
            try {
                // Login context may be null in tests
                if (lc != null) {
                    lc.logout();
                }
            } catch (LoginException e) {
                throw new ClientException("Cannot log out system user", e);
            }
        }
    }

    @Override
    public String getUserName(final String token) {

        // Log in as system user
        LoginContext lc;
        try {
            lc = Framework.login();
        } catch (LoginException e) {
            throw new ClientException("Cannot log in as system user", e);
        }
        try {
            final Session session = Framework.getService(DirectoryService.class).open(
                    DIRECTORY_NAME);
            try {
                DocumentModel entry = session.getEntry(token);
                if (entry == null) {
                    log.debug(String.format(
                            "Found no user name bound to the token: '%s', returning null.",
                            token));
                    return null;
                }
                log.debug(String.format(
                        "Found a user name bound to the token: '%s', returning it.",
                        token));
                return (String) entry.getProperty(DIRECTORY_SCHEMA,
                        USERNAME_FIELD);

            } finally {
                session.close();
            }
        } finally {
            try {
                // Login context may be null in tests
                if (lc != null) {
                    lc.logout();
                }
            } catch (LoginException e) {
                throw new ClientException("Cannot log out system user", e);
            }
        }
    }

    @Override
    public void revokeToken(final String token) {

        // Log in as system user
        LoginContext lc;
        try {
            lc = Framework.login();
        } catch (LoginException e) {
            throw new ClientException("Cannot log in as system user", e);
        }
        try {
            final Session session = Framework.getService(DirectoryService.class).open(
                    DIRECTORY_NAME);
            try {
                session.deleteEntry(token);
                log.info(String.format(
                        "Deleted token: '%s' from the back-end.", token));
            } finally {
                session.close();
            }
        } finally {
            try {
                // Login context may be null in tests
                if (lc != null) {
                    lc.logout();
                }
            } catch (LoginException e) {
                throw new ClientException("Cannot log out system user", e);
            }
        }
    }

    @Override
    public DocumentModelList getTokenBindings(String userName) {

        // Log in as system user
        LoginContext lc;
        try {
            lc = Framework.login();
        } catch (LoginException e) {
            throw new ClientException("Cannot log in as system user", e);
        }
        try {
            final Session session = Framework.getService(DirectoryService.class).open(
                    DIRECTORY_NAME);
            try {
                final Map<String, Serializable> filter = new HashMap<String, Serializable>();
                filter.put(USERNAME_FIELD, userName);
                final Map<String, String> orderBy = new HashMap<String, String>();
                orderBy.put(CREATION_DATE_FIELD, "desc");
                return session.query(filter, Collections.<String> emptySet(),
                        orderBy);
            } finally {
                session.close();
            }
        } finally {
            try {
                // Login context may be null in tests
                if (lc != null) {
                    lc.logout();
                }
            } catch (LoginException e) {
                throw new ClientException("Cannot log out system user", e);
            }
        }
    }

    protected DocumentModel getBareAuthTokenModel(
            DirectoryService directoryService) throws ClientException {

        String directorySchema = directoryService.getDirectorySchema(DIRECTORY_NAME);
        return BaseSession.createEntryModel(null, directorySchema, null, null);
    }

}
