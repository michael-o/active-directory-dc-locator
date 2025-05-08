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
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e6a9efa-6312-44e2-af12-06ad73afbfa5"><code>
 * NETLOGON_NT_VERSION</code></a> options bits.
 */
public enum NetlogonNtVersion implements IntFlag {
	V1(0x00000001, "NETLOGON_NT_VERSION_1"),
	V5(0x00000002, "NETLOGON_NT_VERSION_5"),
	V5EX(0x00000004, "NETLOGON_NT_VERSION_5EX"),
	V5EP(0x00000008, "NETLOGON_NT_VERSION_5EX_WITH_IP"),
	VCS(0x00000010, "NETLOGON_NT_VERSION_WITH_CLOSEST_SITE"),
	VNT4(0x01000000, "NETLOGON_NT_VERSION_AVOID_NT4EMUL"),
	VPDC(0x10000000, "NETLOGON_NT_VERSION_PDC"),
	VIP(0x20000000, "NETLOGON_NT_VERSION_IP"),
	VL(0x40000000, "NETLOGON_NT_VERSION_LOCAL"),
	VGC(0x80000000, "NETLOGON_NT_VERSION_GC");

	private final int intValue;
	private final String fullName;

	NetlogonNtVersion(int intValue, String fullName) {
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
