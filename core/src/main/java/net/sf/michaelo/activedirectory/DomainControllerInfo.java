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
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import net.sf.michaelo.activedirectory.ldapping.DsFlag;

import org.apache.commons.lang3.Validate;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/windows/win32/api/dsgetdc/ns-dsgetdc-domain_controller_infow"><code>
 * DOMAIN_CONTROLLER_INFO</code></a> structure.
 */
public class DomainControllerInfo {

	private String domainControllerName;
	private InetAddress domainControllerAddress;
	private UUID domainGuid;
	private String domainName;
	private String dnsForestName;
	private Set<DsFlag> flags;
	private String dcSiteName;
	private String clientSiteName;

	/**
	 * Constructs the {@code DOMAIN_CONTROLLER_INFO} structure.
	 *
	 * @param domainControllerName the domain conroller name
	 * @param domainControllerAddress the domain controller address
	 * @param domainGuid the domain GUID (UUID)
	 * @param domainName the domain name
	 * @param dnsForestName the DNS forest name
	 * @param flags the DS flags
	 * @param dcSiteName the domain controller site name
	 * @param clientSiteName the client site name
	 * @throws NullPointerException if {@code domainControllerName}, {@code domainGuid}, {@code dnsForestName},
	 *     {@code flags}, or {@code dcSiteName} is null
	 * @throws IllegalArgumentException if {@code domainControllerName}, {@code dnsForestName}, or {@code dcSiteName} is
	 *     empty
	 */
	public DomainControllerInfo(
			String domainControllerName,
			InetAddress domainControllerAddress,
			UUID domainGuid,
			String domainName,
			String dnsForestName,
			Set<DsFlag> flags,
			String dcSiteName,
			String clientSiteName) {
		this.domainControllerName =
				Validate.notEmpty(domainControllerName, "domainControllerName cannot be null or empty");
		this.domainControllerAddress = domainControllerAddress;
		this.domainGuid = Objects.requireNonNull(domainGuid, "domainGuid cannot be null");
		this.domainName = domainName;
		this.dnsForestName = Validate.notEmpty(dnsForestName, "dnsForestName cannot be null or empty");
		this.flags = Collections.unmodifiableSet(flags);
		this.dcSiteName = Validate.notEmpty(dcSiteName, "dcSiteName cannot be null or empty");
		this.clientSiteName = clientSiteName;
	}

	public String getDomainControllerName() {
		return domainControllerName;
	}

	public InetAddress getDomainControllerAddress() {
		return domainControllerAddress;
	}

	public UUID getDomainGuid() {
		return domainGuid;
	}

	public String getDomainName() {
		return domainName;
	}

	public String getDnsForestName() {
		return dnsForestName;
	}

	public Set<DsFlag> getFlags() {
		return flags;
	}

	public String getDcSiteName() {
		return dcSiteName;
	}

	public String getClientSiteName() {
		return clientSiteName;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("DomainControllerInfo[");
		sb.append("domainControllerName: ").append(domainControllerName);
		if (domainControllerAddress != null)
			sb.append(", domainControllerAddress: ").append(domainControllerAddress.getHostAddress());
		sb.append(", domainGuid: ").append(domainGuid);
		if (StringUtils.isNotEmpty(domainName)) sb.append(", domainName: ").append(domainName);
		if (StringUtils.isNotEmpty(dnsForestName))
			sb.append(", dnsForestName: ").append(dnsForestName);
		sb.append(", flags: ").append(IntFlag.toFlagsString(flags));
		sb.append(", dcSiteName: ").append(dcSiteName);
		if (StringUtils.isNotEmpty(clientSiteName))
			sb.append(", clientSiteName: ").append(clientSiteName);
		sb.append("]");
		return sb.toString();
	}
}
