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
package net.sf.michaelo.activedirectory.ldapping;

import java.util.Collections;
import java.util.Set;

import org.apache.commons.lang3.Validate;

/** LDAP ping request for {@link ActiveDirectoryLdapPinger}. */
public class LdapPingRequest {

	private String protocol;
	private String hostName;
	private Set<NetlogonNtVersion> ntVersion;
	private String dnsDomain;
	private String dnsHostName;
	private int connectTimeout = -1;
	private int readTimeout = -1;

	/**
	 * Constructs a minimal LDAP ping request.
	 *
	 * @param hostName the host name from which the request is sent
	 * @param ntVersion the Netlogon NT version flags for the target server
	 * @throws NullPointerException if {@code hostName} is null or {@code ntVersion} is null
	 * @throws IllegalArgumentException if {@code hostName} is empty
	 */
	public LdapPingRequest(String hostName, Set<NetlogonNtVersion> ntVersion) {
		this.hostName = Validate.notEmpty(hostName, "hostName cannot be null or empty");
		this.ntVersion = Collections.unmodifiableSet(ntVersion);
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public void setDnsDomain(String dnsDomain) {
		this.dnsDomain = dnsDomain;
	}

	public void setDnsHostName(String dnsHostName) {
		this.dnsHostName = dnsHostName;
	}

	public void setConnectTimeout(int connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	public void setReadTimeout(int readTimeout) {
		this.readTimeout = readTimeout;
	}

	public String getProtocol() {
		return protocol;
	}

	public String getHostName() {
		return hostName;
	}

	public Set<NetlogonNtVersion> getNtVersion() {
		return ntVersion;
	}

	public String getDnsDomain() {
		return dnsDomain;
	}

	public String getDnsHostName() {
		return dnsHostName;
	}

	public int getConnectTimeout() {
		return connectTimeout;
	}

	public int getReadTimeout() {
		return readTimeout;
	}
}
