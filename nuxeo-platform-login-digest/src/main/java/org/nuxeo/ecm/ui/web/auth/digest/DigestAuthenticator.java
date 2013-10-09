/*
 * (C) Copyright 2010-2011 Nuxeo SA (http://nuxeo.com/) and contributors.
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
 *     Gagnavarslan ehf
 */
package org.nuxeo.ecm.ui.web.auth.digest;

import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import au.com.bytecode.opencsv.CSVReader;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.ui.web.auth.interfaces.NuxeoAuthenticationPlugin;

/**
 * Nuxeo Authenticator for HTTP Digest Access Authentication (RFC 2617).
 */
public class DigestAuthenticator implements NuxeoAuthenticationPlugin {

    private static final Log log = LogFactory.getLog(DigestAuthenticator.class);

    protected static final String DEFAULT_REALMNAME = "NUXEO";

    protected static final long DEFAULT_NONCE_VALIDITY_SECONDS = 1000;

    /*
     * match the first portion up until an equals sign
     * followed by optional white space of quote chars
     * and ending with an optional quote char
     * Pattern is a thread-safe class and so can be defined statically
     * Example pair pattern: username="kirsty"
     */
    protected static final Pattern PAIR_ITEM_PATTERN = Pattern.compile("^(.*?)=([\\s\"]*)?(.*)(\")?$");

    protected static final String REALM_NAME_KEY = "RealmName";

    protected static final String BA_HEADER_NAME = "WWW-Authenticate";

    protected String realmName;

    protected long nonceValiditySeconds = DEFAULT_NONCE_VALIDITY_SECONDS;

    protected String accessKey = "key";

    @Override
    public Boolean handleLoginPrompt(HttpServletRequest httpRequest,
            HttpServletResponse httpResponse, String baseURL) {

        long expiryTime = System.currentTimeMillis()
                + (nonceValiditySeconds * 1000);
        String signature = DigestUtils.md5Hex(expiryTime + ":" + accessKey);
        String nonce = expiryTime + ":" + signature;
        String nonceB64 = new String(Base64.encodeBase64(nonce.getBytes()));

        String authenticateHeader = String.format(
                "Digest realm=\"%s\", qop=\"auth\", nonce=\"%s\"", realmName,
                nonceB64);

        try {
            httpResponse.addHeader(BA_HEADER_NAME, authenticateHeader);
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return Boolean.TRUE;
        } catch (IOException e) {
            return Boolean.FALSE;
        }
    }

    @Override
    public UserIdentificationInfo handleRetrieveIdentity(
            HttpServletRequest httpRequest, HttpServletResponse httpResponse) {

        String header = httpRequest.getHeader("Authorization");
        String DIGEST_PREFIX = "digest ";
        if (StringUtils.isEmpty(header)
                || !header.toLowerCase().startsWith(DIGEST_PREFIX)) {
            return null;
        }
        Map<String, String> headerMap = splitParameters(header.substring(DIGEST_PREFIX.length()));
        headerMap.put("httpMethod", httpRequest.getMethod());

        String nonceB64 = headerMap.get("nonce");
        String nonce = new String(Base64.decodeBase64(nonceB64.getBytes()));
        String[] nonceTokens = nonce.split(":");

        @SuppressWarnings("unused")
        long nonceExpiryTime = Long.parseLong(nonceTokens[0]);
        // @TODO: check expiry time and do something

        String username = headerMap.get("username");
        String responseDigest = headerMap.get("response");
        UserIdentificationInfo userIdent = new UserIdentificationInfo(username,
                responseDigest);

        /*
         * I have used this property to transfer response parameters to
         * DigestLoginPlugin But loginParameters rewritten in
         * NuxeoAuthenticationFilter common implementation
         *
         * @TODO: Fix this or find new way to transfer properties to LoginPlugin
         */
        userIdent.setLoginParameters(headerMap);
        return userIdent;

    }

    @Override
    public Boolean needLoginPrompt(HttpServletRequest httpRequest) {
        // @TODO: Use DIGEST authentication for WebDAV and WSS
        return Boolean.TRUE;
    }

    @Override
    public void initPlugin(Map<String, String> parameters) {
        if (parameters.containsKey(REALM_NAME_KEY)) {
            realmName = parameters.get(REALM_NAME_KEY);
        } else {
            realmName = DEFAULT_REALMNAME;
        }
    }

    @Override
    public List<String> getUnAuthenticatedURLPrefix() {
        return null;
    }

    public static Map<String, String> splitParameters(String auth) {
        Map<String, String> map = new HashMap<String, String>();
        CSVReader reader = null;
        try {
            reader = new CSVReader(new StringReader(auth));
            String[] array = null;
            try {
                array = reader.readNext();
            } catch (IOException e) {
                log.error(e.getMessage(),e);
                return map;
            }
            for (String itemPairStr : array) {
                Matcher match = PAIR_ITEM_PATTERN.matcher(itemPairStr);
                if (match.find()) {
                    String key = match.group(1);
                    String value = match.group(3);
                    map.put(key.trim(), value.trim());
                } else {
                    log.warn("Could not parse item pair " + itemPairStr);
                }
            }
        } finally {
            if (reader!=null) {
                try {
                    reader.close();
                } catch (IOException io) { }
            }
        }
        return map;
    }

}
