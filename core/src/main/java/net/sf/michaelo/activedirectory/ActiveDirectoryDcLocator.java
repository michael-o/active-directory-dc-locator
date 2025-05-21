/*
 * Copyright 2025 Michael Osipov
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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.naming.ConfigurationException;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.ServiceUnavailableException;

import net.sf.michaelo.activedirectory.DcLocatorRequest.Flag;
import net.sf.michaelo.activedirectory.dns.ActiveDirectoryDnsLocator;
import net.sf.michaelo.activedirectory.dns.DnsLocatorRequest;
import net.sf.michaelo.activedirectory.ldapping.ActiveDirectoryLdapPinger;
import net.sf.michaelo.activedirectory.ldapping.DsFlag;
import net.sf.michaelo.activedirectory.ldapping.LdapPingRequest;
import net.sf.michaelo.activedirectory.ldapping.NetlogonNtVersion;
import net.sf.michaelo.activedirectory.ldapping.NetlogonSamLogonExResponse;

/**
 * A Java implementation of the <a
 * href="https://learn.microsoft.com/en-us/archive/technet-wiki/24457.how-domain-controllers-are-located-in-windows">DC
 * locator process</a> by mimicking the <a
 * href="https://learn.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsgetdcnamew"><code>DsGetDcName()</code>
 * </a> function. It utilizes <a
 * href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7fcdce70-5205-44d6-9c3a-260e616a2f04">DNS-based
 * discovery</a> (see {@link ActiveDirectoryDnsLocator}) followed by an LDAP ping (see
 * {@link ActiveDirectoryLdapPinger}).
 *
 * <p>The behavior mimics the mentioned Windows function by observation, traffic captures and Samba's source code
 * inspection, but will never fully cover its functionality. More specifically, the following differs:
 *
 * <ul>
 *   <li>RPCs through {@link DcLocatorRequest#setComputerName(String)} are not supported, thus the location happens on
 *       the local host only. (deprecated for removal)
 *   <li>Flags {@link Flag#DS_FORCE_REDISCOVERY}, {@link Flag#DS_BACKGROUND_ONLY}, {@link Flag#DS_AVOID_SELF},
 *       {@link Flag#DS_DIRECTORY_SERVICE_PREFERRED}, {@link Flag#DS_GOOD_TIMESERV_PREFERRED} are silently ignored.
 *   <li>Flag {@link Flag#DS_IS_FLAT_NAME} is not supported.
 *   <li>Location via GUID is not supported at all.
 * </ul>
 *
 * <p><b>Note</b>: This class uses JUL to print log messages, enable at least level {@code FINE} to see output.
 */
public class ActiveDirectoryDcLocator {

	private static final String PERIOD = ".";

	private static final Set<Flag> IGNORED_FLAGS = Collections.unmodifiableSet(EnumSet.of(
			Flag.DS_FORCE_REDISCOVERY,
			Flag.DS_BACKGROUND_ONLY,
			Flag.DS_AVOID_SELF,
			Flag.DS_DIRECTORY_SERVICE_PREFERRED,
			Flag.DS_GOOD_TIMESERV_PREFERRED));

	private static final Set<Flag> ONLY_LDAP_NEEDED_IGNORED_FLAGS = Collections.unmodifiableSet(EnumSet.of(
			Flag.DS_DIRECTORY_SERVICE_REQUIRED,
			Flag.DS_DIRECTORY_SERVICE_PREFERRED,
			Flag.DS_PDC_REQUIRED,
			Flag.DS_KDC_REQUIRED,
			Flag.DS_TIMESERV_REQUIRED,
			Flag.DS_GOOD_TIMESERV_PREFERRED,
			Flag.DS_DIRECTORY_SERVICE_6_REQUIRED,
			Flag.DS_WEB_SERVICE_REQUIRED,
			Flag.DS_DIRECTORY_SERVICE_8_REQUIRED,
			Flag.DS_DIRECTORY_SERVICE_9_REQUIRED,
			Flag.DS_DIRECTORY_SERVICE_10_REQUIRED,
			Flag.DS_KEY_LIST_SUPPORT_REQUIRED));

	private static final Set<Flag> PDC_REQUIRED_IGNORED_FLAGS =
			Collections.unmodifiableSet(EnumSet.of(Flag.DS_TRY_NEXTCLOSEST_SITE));

	private static final Set<Flag> RETURN_FLAT_NAME_IGNORED_FLAGS =
			Collections.unmodifiableSet(EnumSet.of(Flag.DS_TRY_NEXTCLOSEST_SITE));

	private static final Map<Flag, Set<Flag>> IGNORED_CONDITIONAL_FLAGS_SETS = Collections.unmodifiableMap(Stream.of(
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_ONLY_LDAP_NEEDED, ONLY_LDAP_NEEDED_IGNORED_FLAGS),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_PDC_REQUIRED, PDC_REQUIRED_IGNORED_FLAGS),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_RETURN_FLAT_NAME, RETURN_FLAT_NAME_IGNORED_FLAGS))
			.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));

	private static final Set<Flag> MUTUALLY_EXCLUSIVE_FLAGS_1 = Collections.unmodifiableSet(
			EnumSet.of(Flag.DS_GC_SERVER_REQUIRED, Flag.DS_PDC_REQUIRED, Flag.DS_KDC_REQUIRED));

	private static final Set<Flag> MUTUALLY_EXCLUSIVE_FLAGS_2 =
			Collections.unmodifiableSet(EnumSet.of(Flag.DS_IS_DNS_NAME, Flag.DS_IS_FLAT_NAME));

	private static final Set<Flag> MUTUALLY_EXCLUSIVE_FLAGS_3 =
			Collections.unmodifiableSet(EnumSet.of(Flag.DS_RETURN_DNS_NAME, Flag.DS_RETURN_FLAT_NAME));

	private static final Set<Flag> MUTUALLY_EXCLUSIVE_FLAGS_4 = Collections.unmodifiableSet(EnumSet.of(
			Flag.DS_DIRECTORY_SERVICE_REQUIRED,
			Flag.DS_DIRECTORY_SERVICE_6_REQUIRED,
			Flag.DS_DIRECTORY_SERVICE_8_REQUIRED,
			Flag.DS_DIRECTORY_SERVICE_9_REQUIRED,
			Flag.DS_DIRECTORY_SERVICE_10_REQUIRED));

	private static final Set<Set<Flag>> MUTUALLY_EXCLUSIVE_FLAGS_SETS = Collections.unmodifiableSet(Stream.of(
					MUTUALLY_EXCLUSIVE_FLAGS_1,
					MUTUALLY_EXCLUSIVE_FLAGS_2,
					MUTUALLY_EXCLUSIVE_FLAGS_3,
					MUTUALLY_EXCLUSIVE_FLAGS_4)
			.collect(Collectors.toSet()));

	private static final Set<Flag> GOOD_TIMESERV_PREFERRED_MUTUALLY_EXCLUSIVE_FLAGS =
			Collections.unmodifiableSet(EnumSet.of(
					Flag.DS_GC_SERVER_REQUIRED,
					Flag.DS_PDC_REQUIRED,
					Flag.DS_KDC_REQUIRED,
					Flag.DS_DIRECTORY_SERVICE_REQUIRED));

	private static final Map<Flag, Set<Flag>> MUTUALLY_EXCLUSIVE_CONDITIONAL_FLAGS_SETS =
			Collections.unmodifiableMap(Stream.of(new AbstractMap.SimpleImmutableEntry<>(
							Flag.DS_GOOD_TIMESERV_PREFERRED, GOOD_TIMESERV_PREFERRED_MUTUALLY_EXCLUSIVE_FLAGS))
					.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));

	private static final Map<Flag, DsFlag> SERVER_SELECTION_FLAGS = Collections.unmodifiableMap(Stream.of(
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_DIRECTORY_SERVICE_REQUIRED, DsFlag.FD),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_GC_SERVER_REQUIRED, DsFlag.FG),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_PDC_REQUIRED, DsFlag.FP),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_KDC_REQUIRED, DsFlag.FK),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_TIMESERV_REQUIRED, DsFlag.FT),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_WRITABLE_REQUIRED, DsFlag.FW),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_ONLY_LDAP_NEEDED, DsFlag.FL),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_DIRECTORY_SERVICE_6_REQUIRED, DsFlag.FFS),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_WEB_SERVICE_REQUIRED, DsFlag.FWS),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_DIRECTORY_SERVICE_8_REQUIRED, DsFlag.FW8),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_DIRECTORY_SERVICE_9_REQUIRED, DsFlag.FW9),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_DIRECTORY_SERVICE_10_REQUIRED, DsFlag.FW10),
					new AbstractMap.SimpleImmutableEntry<>(Flag.DS_KEY_LIST_SUPPORT_REQUIRED, DsFlag.FKL))
			.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));

	private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryDcLocator.class.getName());

	private Set<Flag> validateAndReturnFlags(Set<Flag> flags, String siteName) {
		if (flags.isEmpty()) return flags;

		if (StringUtils.isNotEmpty(siteName))
			LOGGER.finer(() ->
					String.format("Validating flags [%s] with site name '%s'", IntFlag.toFlagsString(flags), siteName));
		else LOGGER.finer(() -> String.format("Validating flags [%s]", IntFlag.toFlagsString(flags)));

		// request flags can be null
		Set<Flag> validatedFlags = EnumSet.noneOf(Flag.class);
		validatedFlags.addAll(flags);

		IGNORED_FLAGS.stream().forEach(f -> {
			if (validatedFlags.contains(f)) LOGGER.fine(() -> String.format("Flag '%s' is ignored", f));
		});

		IGNORED_CONDITIONAL_FLAGS_SETS.forEach((f, s) -> {
			if (validatedFlags.contains(f))
				s.stream().forEach(_if -> {
					if (validatedFlags.contains(_if)) {
						LOGGER.fine(
								() -> String.format("Flag '%s' is provided, expliclitly ignoring flag '%s'", f, _if));
						validatedFlags.remove(_if);
					}
				});
		});

		MUTUALLY_EXCLUSIVE_FLAGS_SETS.forEach(s -> {
			Set<Flag> mutuallyExclusiveFlags = validatedFlags.stream()
					.filter(f -> s.contains(f))
					.collect(Collectors.toCollection(() -> EnumSet.noneOf(Flag.class)));
			if (mutuallyExclusiveFlags.size() >= 2)
				throw new IllegalArgumentException(
						String.format("Flags [%s] cannot be combined", IntFlag.toFlagsString(mutuallyExclusiveFlags)));
		});

		MUTUALLY_EXCLUSIVE_CONDITIONAL_FLAGS_SETS.forEach((f, s) -> {
			if (validatedFlags.contains(f)) {
				s.stream().forEach(_mef -> {
					if (validatedFlags.contains(_mef))
						throw new IllegalArgumentException(String.format(
								"Flags [%s] cannot be combined", IntFlag.toFlagsString(EnumSet.of(f, _mef))));
				});
			}
		});

		if (validatedFlags.contains(Flag.DS_KEY_LIST_SUPPORT_REQUIRED)
				&& !validatedFlags.contains(Flag.DS_KDC_REQUIRED))
			throw new IllegalArgumentException(String.format(
					"Flag '%s' requires flag '%s' to be set", Flag.DS_KEY_LIST_SUPPORT_REQUIRED, Flag.DS_KDC_REQUIRED));

		if (validatedFlags.contains(Flag.DS_RETURN_DNS_NAME) && !validatedFlags.contains(Flag.DS_IP_REQUIRED)) {
			LOGGER.fine(() -> String.format(
					"Flag '%s' is provided, implicitly setting flag '%s'",
					Flag.DS_RETURN_DNS_NAME, Flag.DS_IP_REQUIRED));
			validatedFlags.add(Flag.DS_IP_REQUIRED);
		}

		if (validatedFlags.contains(Flag.DS_IS_FLAT_NAME))
			throw new IllegalArgumentException(String.format("Flag '%s' is not supported", Flag.DS_IS_FLAT_NAME));

		if (StringUtils.isNotEmpty(siteName) && validatedFlags.contains(Flag.DS_TRY_NEXTCLOSEST_SITE))
			throw new IllegalArgumentException(String.format(
					"Flag '%s' cannot be combined with site-specific discovery", Flag.DS_TRY_NEXTCLOSEST_SITE));

		return validatedFlags;
	}

	private static String getFullyQualifiedLocalHostName() throws NamingException {
		try {
			InetAddress localHost = InetAddress.getLocalHost();
			String hostName = localHost.getHostName();
			if (!hostName.contains(PERIOD)) {
				hostName = localHost.getCanonicalHostName();
			}

			return hostName;
		} catch (UnknownHostException e) {
			NamingException ne = new ConfigurationException("Failed to get fully-qualified local host name");
			ne.initCause(e);
			throw ne;
		}
	}

	/**
	 * Locates a suitable domain controller.
	 *
	 * @param request the DC locator request
	 * @return the located domain controller information, never null
	 * @throws NullPointerException if {@code request} is null
	 * @throws OperationNotSupportedException if {@code DcLocatorRequest#getComputerName()} is not null
	 * @throws ConfigurationException if the {@code request} contains incompatible parameters or the local host name
	 *     could not be determined
	 * @throws NamingException if the locator process has failed, cause may contain details
	 */
	public DomainControllerInfo locate(DcLocatorRequest request) throws NamingException {
		Objects.requireNonNull(request, "request cannot be null");

		String computerName = request.getComputerName();
		String domainName = request.getDomainName();
		String siteName = request.getSiteName();
		int readTimeout = request.getReadTimeout();

		if (StringUtils.isNotEmpty(computerName))
			throw new OperationNotSupportedException(
					String.format("RPC communication to '%s' is not supported", computerName));

		computerName = getFullyQualifiedLocalHostName();

		if (!computerName.contains(PERIOD))
			throw new ConfigurationException("computerName must be fully qualified: " + computerName);

		if (StringUtils.isNotEmpty(domainName)) {
			if (!domainName.endsWith(PERIOD) && !domainName.contains(PERIOD))
				throw new ConfigurationException("domainName must be fully qualified: " + domainName);

			if (domainName.endsWith(PERIOD)
					&& !domainName.substring(0, domainName.length() - 1).contains(PERIOD))
				throw new ConfigurationException("domainName must be fully qualified: " + domainName);
		}

		Set<Flag> flags = null;
		try {
			flags = validateAndReturnFlags(request.getFlags(), siteName);
		} catch (IllegalArgumentException e) {
			NamingException ne = new ConfigurationException(e.getMessage());
			ne.setStackTrace(e.getStackTrace());
			throw ne;
		}

		ActiveDirectoryDnsLocator dnsLocator =
				new ActiveDirectoryDnsLocator.Builder().readTimeout(readTimeout).build();

		DomainControllerInfo dcInfo = null;
		if (flags.contains(Flag.DS_ONLY_LDAP_NEEDED)) {
			dcInfo = locateServer(
					flags.contains(Flag.DS_GC_SERVER_REQUIRED) ? "gc" : "ldap",
					null,
					flags.contains(Flag.DS_GC_SERVER_REQUIRED) ? "GC-only" : "LDAP-only",
					dnsLocator,
					flags,
					computerName,
					domainName,
					siteName,
					readTimeout);
		} else if (flags.contains(Flag.DS_PDC_REQUIRED)) {
			dcInfo = locatePdcServer(dnsLocator, flags, computerName, domainName, siteName, readTimeout);
		} else if (flags.contains(Flag.DS_GC_SERVER_REQUIRED)) {
			dcInfo = locateServer(
					"ldap", "gc", "GC", dnsLocator, flags, computerName, domainName, siteName, readTimeout);
		} else if (flags.contains(Flag.DS_KDC_REQUIRED)) {
			dcInfo = locateServer(
					"kerberos", "dc", "KDC", dnsLocator, flags, computerName, domainName, siteName, readTimeout);
		} else if (flags.contains(Flag.DS_DIRECTORY_SERVICE_REQUIRED)) {
			dcInfo = locateServer(
					"ldap", "dc", "DS", dnsLocator, flags, computerName, domainName, siteName, readTimeout);
		} else {
			dcInfo = locateServer(
					"ldap", "dc", "DS", dnsLocator, flags, computerName, domainName, siteName, readTimeout);
		}

		return dcInfo;
	}

	private DomainControllerInfo locateServer(
			String service,
			String dcType,
			String serviceName,
			ActiveDirectoryDnsLocator dnsLocator,
			Set<Flag> flags,
			String computerName,
			String domainName,
			String siteName,
			int readTimeout)
			throws NamingException {
		final String _domainName = domainName;
		final String _siteName = siteName;
		LOGGER.fine(() -> {
			StringBuilder sb = new StringBuilder("Locating ").append(serviceName);
			sb.append(" server in ");
			if (StringUtils.isNotEmpty(_domainName))
				sb.append("domain '").append(_domainName).append("'");
			else sb.append("default domain");
			if (StringUtils.isNotEmpty(_siteName))
				sb.append(" and site '").append(_siteName).append("'");
			else sb.append(" and default site");

			return sb.toString();
		});

		if (StringUtils.isNotEmpty(siteName)) {
			if (StringUtils.isEmpty(domainName)) {
				domainName = computerName.substring(computerName.indexOf(PERIOD) + 1);
				// We need to find the DNS forest name if we only have the DNS domain name through an LDAP ping
				if (flags.contains(Flag.DS_GC_SERVER_REQUIRED))
					domainName =
							determineForestName(dnsLocator, flags, computerName, domainName, siteName, readTimeout);
			}

			DnsLocatorRequest dnsRequest = new DnsLocatorRequest(service, domainName);
			dnsRequest.setSiteName(siteName);
			dnsRequest.setDcType(dcType);
			InetSocketAddress[] hostAddresses = null;
			try {
				hostAddresses = dnsLocator.locate(dnsRequest);
			} catch (NamingException e) {
				throw newNamingException(domainName, siteName, e);
			}

			NetlogonSamLogonExResponse pingResponse =
					selectServer(hostAddresses, flags, computerName, domainName, null, readTimeout);

			if (pingResponse == null)
				throw newNamingException(
						domainName,
						siteName,
						new ServiceUnavailableException(String.format(
								"Failed to probe %d server%s",
								hostAddresses.length, hostAddresses.length == 1 ? "" : "s")));

			DomainControllerInfo dcInfo = toDomainControllerInfo(pingResponse, flags, siteName);

			if (LOGGER.isLoggable(Level.FINER))
				LOGGER.finer(() -> String.format("Located %s server: %s", serviceName, dcInfo));
			else
				LOGGER.fine(
						() -> String.format("Located %s server '%s'", serviceName, dcInfo.getDomainControllerName()));

			return dcInfo;
		} else {
			if (StringUtils.isEmpty(domainName)) {
				domainName = computerName.substring(computerName.indexOf(PERIOD) + 1);
				// We need to find the DNS forest name if we only have the DNS domain name through an LDAP ping
				if (flags.contains(Flag.DS_GC_SERVER_REQUIRED))
					domainName = determineForestName(dnsLocator, flags, computerName, domainName, null, readTimeout);
			}

			final String __domainName = domainName;
			LOGGER.fine(() -> String.format("Locating site name for domain '%s'", __domainName));
			DnsLocatorRequest dnsRequest = new DnsLocatorRequest(service, domainName);
			dnsRequest.setDcType(dcType);
			InetSocketAddress[] hostAddresses = null;
			try {
				hostAddresses = dnsLocator.locate(dnsRequest);
			} catch (NamingException e) {
				throw newNamingException(domainName, null, e);
			}

			NetlogonSamLogonExResponse pingResponse = selectServer(
					hostAddresses, EnumSet.noneOf(Flag.class), computerName, domainName, null, readTimeout);

			if (pingResponse == null)
				throw newNamingException(
						domainName,
						null,
						new ServiceUnavailableException(String.format(
								"Failed to probe %d server%s",
								hostAddresses.length, hostAddresses.length == 1 ? "" : "s")));

			siteName = pingResponse.getClientSiteName();
			String nextClosestSiteName = pingResponse.getNextClosestSiteName();
			String selectedSiteName = null;

			final String __siteName = siteName;
			LOGGER.fine(() -> {
				if (StringUtils.isNotEmpty(__siteName)) {
					StringBuilder sb = new StringBuilder("Client is in site '")
							.append(__siteName)
							.append("'");
					if (StringUtils.isNotEmpty(nextClosestSiteName))
						sb.append(" and has next closest site '")
								.append(nextClosestSiteName)
								.append("'");
					return sb.toString();
				} else return "Client has no default site";
			});

			pingResponse = null;
			int locatedServersCount = 0;
			if (StringUtils.isNotEmpty(siteName)) {
				dnsRequest = new DnsLocatorRequest(service, domainName);
				dnsRequest.setSiteName(siteName);
				dnsRequest.setDcType(dcType);
				hostAddresses = null;
				try {
					hostAddresses = dnsLocator.locate(dnsRequest);
				} catch (NamingException e) {
					LOGGER.log(Level.FINE, e, () -> "Failed to locate servers, trying fallback");
				}

				if (hostAddresses != null) {
					locatedServersCount += hostAddresses.length;
					pingResponse = selectServer(hostAddresses, flags, computerName, domainName, null, readTimeout);
					selectedSiteName = siteName;
				}

				if (pingResponse == null)
					LOGGER.fine(
							() -> String.format("No %s server located in client site, trying fallback", serviceName));

				if (pingResponse == null
						&& flags.contains(Flag.DS_TRY_NEXTCLOSEST_SITE)
						&& StringUtils.isNotEmpty(nextClosestSiteName)) {
					dnsRequest = new DnsLocatorRequest(service, domainName);
					dnsRequest.setSiteName(nextClosestSiteName);
					dnsRequest.setDcType(dcType);
					hostAddresses = null;
					try {
						hostAddresses = dnsLocator.locate(dnsRequest);
					} catch (NamingException e) {
						LOGGER.log(Level.FINE, e, () -> "Failed to locate servers, trying fallback");
					}

					if (hostAddresses != null) {
						locatedServersCount += hostAddresses.length;
						pingResponse = selectServer(hostAddresses, flags, computerName, domainName, null, readTimeout);
						selectedSiteName = nextClosestSiteName;
					}

					if (pingResponse == null)
						LOGGER.fine(() -> String.format(
								"No %s server located in next closest site, trying fallback", serviceName));
				}
			}

			if (pingResponse == null) {
				dnsRequest = new DnsLocatorRequest(service, domainName);
				dnsRequest.setDcType(dcType);
				hostAddresses = null;
				try {
					hostAddresses = dnsLocator.locate(dnsRequest);
				} catch (NamingException e) {
					throw newNamingException(domainName, null, e);
				}

				locatedServersCount += hostAddresses.length;
				pingResponse = selectServer(hostAddresses, flags, computerName, domainName, null, readTimeout);
				selectedSiteName = null;
			}

			if (pingResponse == null)
				throw newNamingException(
						domainName,
						null,
						new ServiceUnavailableException(String.format(
								"Failed to probe %d server%s (combined)",
								locatedServersCount, locatedServersCount == 1 ? "" : "s")));

			DomainControllerInfo dcInfo = toDomainControllerInfo(pingResponse, flags, selectedSiteName);

			if (LOGGER.isLoggable(Level.FINER))
				LOGGER.finer(() -> String.format("Located %s server: %s", serviceName, dcInfo));
			else
				LOGGER.fine(
						() -> String.format("Located %s server '%s'", serviceName, dcInfo.getDomainControllerName()));

			return dcInfo;
		}
	}

	private String determineForestName(
			ActiveDirectoryDnsLocator dnsLocator,
			Set<Flag> flags,
			String computerName,
			String domainName,
			String siteName,
			int readTimeout)
			throws NamingException {
		final String __domainName = domainName;
		final String __siteName = siteName;
		if (StringUtils.isNotEmpty(siteName))
			LOGGER.fine(() ->
					String.format("Locating forest name for domain '%s' and site '%s'", __domainName, __siteName));
		else LOGGER.fine(() -> String.format("Locating forest name for domain '%s'", __domainName));
		DnsLocatorRequest dnsRequest = new DnsLocatorRequest("ldap", domainName);
		dnsRequest.setSiteName(siteName);
		dnsRequest.setDcType(!flags.contains(Flag.DS_ONLY_LDAP_NEEDED) ? "dc" : null);
		InetSocketAddress[] hostAddresses = null;
		try {
			hostAddresses = dnsLocator.locate(dnsRequest);
		} catch (NamingException e) {
			throw newNamingException(domainName, siteName, e);
		}

		NetlogonSamLogonExResponse pingResponse =
				selectServer(hostAddresses, EnumSet.noneOf(Flag.class), computerName, domainName, null, readTimeout);

		if (pingResponse == null)
			throw newNamingException(
					domainName,
					siteName,
					new ServiceUnavailableException(String.format(
							"Failed to probe %d server%s",
							hostAddresses.length, hostAddresses.length == 1 ? "" : "s")));

		String forestName = pingResponse.getDnsForestName();
		String _forestName = forestName;
		if (StringUtils.isNotEmpty(siteName))
			LOGGER.fine(() -> String.format(
					"Domain '%s' and site '%s' are in forest '%s'", __domainName, __siteName, _forestName));
		else LOGGER.fine(() -> String.format("Domain '%s' is in forest '%s'", __domainName, _forestName));

		return forestName;
	}

	private DomainControllerInfo locatePdcServer(
			ActiveDirectoryDnsLocator dnsLocator,
			Set<Flag> flags,
			String computerName,
			String domainName,
			String siteName,
			int readTimeout)
			throws NamingException {
		String service = "ldap";
		String dcType = "pdc";
		String serviceName = "PDC";

		final String _domainName = domainName;
		final String _siteName = siteName;
		LOGGER.fine(() -> {
			StringBuilder sb = new StringBuilder("Locating ").append(serviceName);
			sb.append(" server in ");
			if (StringUtils.isNotEmpty(_domainName))
				sb.append("domain '").append(_domainName).append("'");
			else sb.append("default domain");
			if (StringUtils.isNotEmpty(_siteName))
				sb.append(" and site '").append(_siteName).append("'");

			return sb.toString();
		});

		if (StringUtils.isNotEmpty(siteName)) {
			if (StringUtils.isEmpty(domainName)) domainName = computerName.substring(computerName.indexOf(PERIOD) + 1);

			DnsLocatorRequest dnsRequest = new DnsLocatorRequest(service, domainName);
			dnsRequest.setDcType(dcType);
			InetSocketAddress[] hostAddresses = null;
			try {
				hostAddresses = dnsLocator.locate(dnsRequest);
			} catch (NamingException e) {
				throw newNamingException(domainName, siteName, e);
			}

			NetlogonSamLogonExResponse pingResponse =
					selectServer(hostAddresses, flags, computerName, domainName, siteName, readTimeout);

			if (pingResponse == null)
				throw newNamingException(
						domainName,
						siteName,
						new ServiceUnavailableException(String.format(
								"Failed to probe %d server%s",
								hostAddresses.length, hostAddresses.length == 1 ? "" : "s")));

			DomainControllerInfo dcInfo = toDomainControllerInfo(pingResponse, flags, siteName);

			if (LOGGER.isLoggable(Level.FINER))
				LOGGER.finer(() -> String.format("Located %s server: %s", serviceName, dcInfo));
			else
				LOGGER.fine(
						() -> String.format("Located %s server '%s'", serviceName, dcInfo.getDomainControllerName()));

			return dcInfo;
		} else {
			if (StringUtils.isEmpty(domainName)) domainName = computerName.substring(computerName.indexOf(PERIOD) + 1);

			DnsLocatorRequest dnsRequest = new DnsLocatorRequest(service, domainName);
			dnsRequest.setDcType(dcType);
			InetSocketAddress[] hostAddresses = null;
			try {
				hostAddresses = dnsLocator.locate(dnsRequest);
			} catch (NamingException e) {
				throw newNamingException(domainName, null, e);
			}

			NetlogonSamLogonExResponse pingResponse =
					selectServer(hostAddresses, flags, computerName, domainName, null, readTimeout);

			if (pingResponse == null)
				throw newNamingException(
						domainName,
						null,
						new ServiceUnavailableException(String.format(
								"Failed to probe %d server%s",
								hostAddresses.length, hostAddresses.length == 1 ? "" : "s")));

			DomainControllerInfo dcInfo = toDomainControllerInfo(pingResponse, flags, null);

			if (LOGGER.isLoggable(Level.FINER))
				LOGGER.finer(() -> String.format("Located %s server: %s", serviceName, dcInfo));
			else
				LOGGER.fine(
						() -> String.format("Located %s server '%s'", serviceName, dcInfo.getDomainControllerName()));

			return dcInfo;
		}
	}

	// TODO Do we need a 'boolean tryClosestServer' when we are querying non-site servers?
	private NetlogonSamLogonExResponse selectServer(
			InetSocketAddress[] hostAddresses,
			Set<Flag> flags,
			String computerName,
			String domainName,
			String matchSiteName,
			int readTimeout) {
		ActiveDirectoryLdapPinger pinger = new ActiveDirectoryLdapPinger();
		NetlogonSamLogonExResponse pingResponse = null;
		if (LOGGER.isLoggable(Level.FINER))
			LOGGER.finer(() -> String.format(
					"Selecting from %s server%s: [%s]",
					hostAddresses.length,
					hostAddresses.length == 1 ? "" : "s",
					Arrays.stream(hostAddresses).map(ha -> ha.getHostString()).collect(Collectors.joining(", "))));
		else
			LOGGER.fine(() -> String.format(
					"Selecting from %s server%s", hostAddresses.length, hostAddresses.length == 1 ? "" : "s"));

		for (InetSocketAddress hostAddress : hostAddresses) {
			Set<NetlogonNtVersion> ntVersion = EnumSet.of(NetlogonNtVersion.V5EX, NetlogonNtVersion.VCS);
			if (flags.contains(Flag.DS_IP_REQUIRED)) ntVersion.add(NetlogonNtVersion.V5EP);
			if (flags.contains(Flag.DS_GC_SERVER_REQUIRED)) ntVersion.add(NetlogonNtVersion.VGC);
			if (flags.contains(Flag.DS_PDC_REQUIRED)) ntVersion.add(NetlogonNtVersion.VPDC);
			LdapPingRequest pingRequest = new LdapPingRequest(hostAddress.getHostString(), ntVersion);
			pingRequest.setDnsHostName(computerName);
			pingRequest.setDnsDomain(domainName);
			pingRequest.setReadTimeout(readTimeout);

			try {
				LOGGER.fine(() -> String.format("Probing server '%s'", hostAddress.getHostString()));
				pingResponse = (NetlogonSamLogonExResponse) pinger.ping(pingRequest);
				Set<DsFlag> dsFlags = pingResponse.getFlags();

				boolean skip = SERVER_SELECTION_FLAGS.entrySet().stream().anyMatch(e -> {
					boolean _skip = flags.contains(e.getKey()) && !dsFlags.contains(e.getValue());
					if (_skip)
						LOGGER.fine(() -> String.format(
								"Skipping server '%s', it does not have required flag '%s'",
								hostAddress.getHostString(), e.getValue()));

					return _skip;
				});

				if (StringUtils.isNotEmpty(matchSiteName)
						&& !pingResponse.getDcSiteName().equalsIgnoreCase(matchSiteName)) {
					skip = true;
					LOGGER.fine(() -> String.format(
							"Skipping server '%s', it is not in site '%s'",
							hostAddress.getHostString(), matchSiteName));
				}

				if (skip) {
					pingResponse = null;
					continue;
				}
				break;
			} catch (NamingException e) {
				LOGGER.log(
						Level.FINE, e, () -> String.format("Failed to probe server '%s'", hostAddress.getHostString()));
			}
		}

		if (pingResponse != null) {
			String hostName = pingResponse.getDnsHostName();
			LOGGER.fine(() -> String.format("Selected server '%s'", hostName));
		} else LOGGER.fine(() -> "No server selected");

		return pingResponse;
	}

	private NamingException newNamingException(String domainName, String siteName, Throwable cause) {
		StringBuilder sb = new StringBuilder("Domain '").append(domainName).append("'");
		if (StringUtils.isNotEmpty(siteName))
			sb.append(" and site '").append(siteName).append("'");
		sb.append(" either do");
		if (StringUtils.isEmpty(siteName)) sb.append("es");
		sb.append(" not exist or could not be contacted");

		NamingException ne = new NamingException(sb.toString());
		ne.initCause(cause);

		return ne;
	}

	private DomainControllerInfo toDomainControllerInfo(
			NetlogonSamLogonExResponse pingResponse, Set<Flag> flags, String siteName) {
		String domainControllerName = null;
		String domainName = null;

		Set<DsFlag> dsFlags = EnumSet.copyOf(pingResponse.getFlags());
		dsFlags.add(DsFlag.FF);
		if (flags.contains(Flag.DS_RETURN_FLAT_NAME)) {
			domainControllerName = pingResponse.getNetbiosComputerName();
			domainName = pingResponse.getNetbiosDomainName();
		} else {
			dsFlags.add(DsFlag.FDNS);
			dsFlags.add(DsFlag.FDM);
			domainControllerName = pingResponse.getDnsHostName();
			domainName = pingResponse.getDnsDomainName();
		}

		if (pingResponse.getDcSiteName().equalsIgnoreCase(siteName)) dsFlags.add(DsFlag.FC);

		return new DomainControllerInfo(
				domainControllerName,
				pingResponse.getDcSockAddr(),
				pingResponse.getDomainGuid(),
				domainName,
				pingResponse.getDnsForestName(),
				dsFlags,
				pingResponse.getDcSiteName(),
				pingResponse.getClientSiteName());
	}
}
