/*
 * Copyright 2016–2025 Michael Osipov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.sf.michaelo.activedirectory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import javax.naming.ConfigurationException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;

import com.sun.jndi.ldap.spi.LdapDnsProvider;
import com.sun.jndi.ldap.spi.LdapDnsProviderResult;

import net.sf.michaelo.activedirectory.DcLocatorRequest.Flag;

/**
 * An {@link LdapDnsProvider} for Active Directory. This implementation hooks into Sun's/Oracle's LDAP implementation of
 * JNDI to autodiscover Active Directory servers via the DC locator process.
 *
 * <p>This provider receives all environment properties via JNDI. It recognizes the following properties:
 *
 * <ul>
 *   <li>{@code net.sf.michaelo.activedirectory.readTimeout}: Read timeout for DC locator requests.
 * </ul>
 *
 * <p>Note: This provider will return the input as-is if nothing can be located in the case that a simple host name has
 * been provided.
 */
@SuppressWarnings("restriction")
public class ActiveDirectoryLdapDnsProvider extends LdapDnsProvider {

	public static final String READ_TIMEOUT_PROPERTY = "net.sf.michaelo.activedirectory.readTimeout";

	private static final String LDAP_SCHEME = "ldap";
	private static final String LDAPS_SCHEME = "ldaps";
	private static final String GC_SCHEME = "gc";
	private static final String GCS_SCHEME = "gcs";
	private static final int GC_PORT = 3268;
	private static final int GCS_PORT = 3269;

	private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryLdapDnsProvider.class.getName());

	@Override
	public Optional<LdapDnsProviderResult> lookupEndpoints(String url, Map<?, ?> env) throws NamingException {
		Objects.requireNonNull(url, "url cannot be null");
		Objects.requireNonNull(env, "env cannot be null");

		URI ldapUri = null;
		try {
			ldapUri = URI.create(url);
		} catch (IllegalArgumentException e) {
			NamingException ne = new ConfigurationException("URL '" + url + "' is invalid");
			ne.initCause(e);
			throw ne;
		}

		String val = (String) env.get(READ_TIMEOUT_PROPERTY);
		int readTimeout = (val == null) ? -1 : Integer.parseInt(val);

		ActiveDirectoryDcLocator locator = new ActiveDirectoryDcLocator();
		DcLocatorRequest request = new DcLocatorRequest();
		request.addFlag(Flag.DS_ONLY_LDAP_NEEDED);
		request.addFlag(Flag.DS_RETURN_DNS_NAME);
		request.addFlag(Flag.DS_TRY_NEXTCLOSEST_SITE);
		request.setReadTimeout(readTimeout);

		String scheme = ldapUri.getScheme();
		String domainName = ldapUri.getHost();
		String path = ldapUri.getRawPath();
		String baseDnStr = StringUtils.isNotEmpty(path) ? path.replaceFirst("/", "") : "";
		int port = ldapUri.getPort();

		if (StringUtils.isEmpty(domainName) && StringUtils.isNotEmpty(baseDnStr)) {
			LdapName baseDn = new LdapName(baseDnStr);
			List<String> dcs = baseDn.getRdns().stream()
					.filter(rdn -> rdn.getType().equalsIgnoreCase("DC"))
					.map(rdn -> (String) rdn.getValue())
					.collect(Collectors.toList());
			Collections.reverse(dcs);
			domainName = String.join(".", dcs);
		}
		request.setDomainName(domainName);

		boolean isGcServerRequired = false;
		if (scheme.equalsIgnoreCase(LDAP_SCHEME) && port == GC_PORT
				|| scheme.equalsIgnoreCase(LDAPS_SCHEME) && port == GCS_PORT) isGcServerRequired = true;
		else if (scheme.equalsIgnoreCase(GC_SCHEME)) {
			isGcServerRequired = true;
			scheme = LDAP_SCHEME;
			port = port == -1 ? GC_PORT : port;
		} else if (scheme.equalsIgnoreCase(GCS_SCHEME)) {
			isGcServerRequired = true;
			scheme = LDAPS_SCHEME;
			port = port == -1 ? GCS_PORT : port;
		}
		if (isGcServerRequired) request.addFlag(Flag.DS_GC_SERVER_REQUIRED);

		try {
			LOGGER.fine(() -> String.format("Locating a server for '%s'", url));
			DomainControllerInfo dcInfo = locator.locate(request);
			LOGGER.fine(() -> String.format("Successfully located a server for '%s': %s", url, dcInfo));
			try {
				URI endpointUri = new URI(
						scheme,
						null,
						dcInfo.getDomainControllerName(),
						port,
						path,
						ldapUri.getQuery(),
						ldapUri.getFragment());
				String _domainName = isGcServerRequired ? dcInfo.getDnsForestName() : dcInfo.getDomainName();
				String endpoint = endpointUri.toASCIIString();
				LOGGER.fine(() -> String.format("Returning domainName '%s' with endpoint '%s'", _domainName, endpoint));
				// This is poorly documented, it conflates domain (names) with actual endpoint hostnames, so which is
				// required?
				return Optional.of(new LdapDnsProviderResult(_domainName, Arrays.asList(endpoint)));
			} catch (URISyntaxException e) {
				NamingException ne = new NamingException("Failed to construct endpoint URL");
				ne.initCause(e);
				throw ne;
			}
		} catch (NamingException e) {
			LOGGER.log(Level.FINE, e, () -> "Failed to locate a server, returning original as fallback...");
			return Optional.of(new LdapDnsProviderResult("", Arrays.asList(url)));
		}
	}
}
