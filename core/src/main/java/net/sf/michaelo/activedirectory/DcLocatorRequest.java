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

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * DC locator request for {@link ActiveDirectoryDcLocator}. The parameters represent the arguments for <a
 * href="https://learn.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsgetdcnamea"><code>DsGetDcName()</code>
 * </a> function.
 */
public class DcLocatorRequest {

	/**
	 * The DC locator flags as documented in <a
	 * href="https://learn.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsgetdcnamew#parameters">here</a>.
	 */
	public enum Flag implements IntFlag {
		DS_FORCE_REDISCOVERY(0x00000001),
		DS_DIRECTORY_SERVICE_REQUIRED(0x00000010),
		DS_DIRECTORY_SERVICE_PREFERRED(0x00000020),
		DS_GC_SERVER_REQUIRED(0x00000040),
		DS_PDC_REQUIRED(0x00000080),
		DS_BACKGROUND_ONLY(0x00000100),
		DS_IP_REQUIRED(0x00000200),
		DS_KDC_REQUIRED(0x00000400),
		DS_TIMESERV_REQUIRED(0x00000800),
		DS_WRITABLE_REQUIRED(0x00001000),
		DS_GOOD_TIMESERV_PREFERRED(0x00002000),
		DS_AVOID_SELF(0x00004000),
		DS_ONLY_LDAP_NEEDED(0x00008000),
		DS_IS_FLAT_NAME(0x00010000),
		DS_IS_DNS_NAME(0x00020000),
		DS_TRY_NEXTCLOSEST_SITE(0x00040000),
		DS_DIRECTORY_SERVICE_6_REQUIRED(0x00080000),
		DS_WEB_SERVICE_REQUIRED(0x00100000),
		DS_DIRECTORY_SERVICE_8_REQUIRED(0x00200000),
		DS_DIRECTORY_SERVICE_9_REQUIRED(0x00400000),
		DS_DIRECTORY_SERVICE_10_REQUIRED(0x00800000),
		// This is not documented: https://nettools.net/nltest-flags-what-does-0x20000-mean/
		DS_KEY_LIST_SUPPORT_REQUIRED(0x01000000),
		DS_RETURN_DNS_NAME(0x40000000),
		DS_RETURN_FLAT_NAME(0x80000000);

		private int intValue;

		Flag(int intValue) {
			this.intValue = intValue;
		}

		public int intValue() {
			return intValue;
		}
	}

	@Deprecated
	private String computerName;

	private String domainName;
	private String siteName;
	private Set<Flag> flags;
	private int readTimeout = -1;

	public DcLocatorRequest() {
		flags = EnumSet.noneOf(Flag.class);
	}

	@Deprecated
	public void setComputerName(String computerName) {
		this.computerName = computerName;
	}

	public void setDomainName(String domainName) {
		this.domainName = domainName;
	}

	public void setSiteName(String siteName) {
		this.siteName = siteName;
	}

	public void addFlag(Flag flag) {
		this.flags.add(flag);
	}

	public void setReadTimeout(int readTimeout) {
		this.readTimeout = readTimeout;
	}

	@Deprecated
	public String getComputerName() {
		return computerName;
	}

	public String getDomainName() {
		return domainName;
	}

	public String getSiteName() {
		return siteName;
	}

	public Set<Flag> getFlags() {
		return Collections.unmodifiableSet(flags);
	}

	public int getReadTimeout() {
		return readTimeout;
	}
}
