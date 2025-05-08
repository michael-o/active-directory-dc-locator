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

import net.sf.michaelo.activedirectory.IntFlag;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f55d3f53-351d-4407-940e-f53eb6154af0"><code>
 * DS_FLAG</code></a> options bits.
 */
public enum DsFlag implements IntFlag {
	FP(0x00000001, "DS_PDC_FLAG"),
	FG(0x00000004, "DS_GC_FLAG"),
	FL(0x00000008, "DS_LDAP_FLAG"),
	FD(0x00000010, "DS_DS_FLAG"),
	FK(0x00000020, "DS_KDC_FLAG"),
	FT(0x00000040, "DS_TIMESERV_FLAG"),
	FC(0x00000080, "DS_CLOSEST_FLAG"),
	FW(0x00000100, "DS_WRITABLE_FLAG"),
	FGT(0x00000200, "DS_GOOD_TIMESERV_FLAG"),
	FN(0x00000400, "DS_NDNC_FLAG"),
	FSS(0x00000800, "DS_SELECT_SECRET_DOMAIN_6_FLAG"),
	FFS(0x00001000, "DS_FULL_SECRET_DOMAIN_6_FLAG"),
	FWS(0x00002000, "DS_WS_FLAG"),
	FW8(0x00004000, "DS_DS_8_FLAG"),
	FW9(0x00008000, "DS_DS_9_FLAG"),
	FW10(0x00010000, "DS_DS_10_FLAG"),
	// This is not documented: https://nettools.net/nltest-flags-what-does-0x20000-mean/
	FKL(0x00020000, "DS_KEY_LIST_FLAG"),
	// Flags returned on ping: int DS_PING_FLAGS = 0x000FFFFF
	FDNS(0x20000000, "DS_DNS_CONTROLLER_FLAG"),
	FDM(0x40000000, "DS_DNS_DOMAIN_FLAG"),
	FF(0x80000000, "DS_DNS_FOREST_FLAG");

	private final int intValue;
	private final String fullName;

	DsFlag(int intValue, String fullName) {
		this.intValue = intValue;
		this.fullName = fullName;
	}

	public int intValue() {
		return intValue;
	}

	public String fullName() {
		return fullName;
	}
}
