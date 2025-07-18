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
package net.sf.michaelo.activedirectory.dns;

import org.apache.commons.lang3.Validate;

/** DNS locator request for {@link ActiveDirectoryDnsLocator}. */
public class DnsLocatorRequest {

	private String service;
	private String protocol;
	private String siteName;
	private String dcType;
	private String domainName;

	/**
	 * Constructs a minimal DNS locator request.
	 *
	 * @param service the service
	 * @param domainName the domain name
	 * @throws NullPointerException if {@code service} or {@code domainName} is null
	 * @throws IllegalArgumentException if {@code service} or {@code domainName} is empty
	 */
	public DnsLocatorRequest(String service, String domainName) {
		this.service = Validate.notEmpty(service, "service cannot be null or empty");
		this.domainName = Validate.notEmpty(domainName, "domainName cannot be null or empty");
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public void setSiteName(String siteName) {
		this.siteName = siteName;
	}

	public void setDcType(String dcType) {
		this.dcType = dcType;
	}

	public String getService() {
		return service;
	}

	public String getProtocol() {
		return protocol;
	}

	public String getSiteName() {
		return siteName;
	}

	public String getDcType() {
		return dcType;
	}

	public String getDomainName() {
		return domainName;
	}
}
