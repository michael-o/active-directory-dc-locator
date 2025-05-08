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

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import net.sf.michaelo.activedirectory.IntFlag;
import net.sf.michaelo.activedirectory.StringUtils;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9c5a9e2c-2aae-40e2-8fcb-b9dfc032ac3b"><code>
 * NETLOGON_SAM_LOGON_RESPONSE_NT40</code></a> structure.
 */
public class NetlogonSamLogonNt40Response extends NetlogonSamLogonBaseResponse {

	private static final Set<NetlogonNtVersion> NETLOGON_NT_VERSION_1 =
			Collections.unmodifiableSet(EnumSet.of(NetlogonNtVersion.V1));

	private String unicodeLogonServer;
	private String unicodeUserName;
	private String unicodeDomainName;

	public NetlogonSamLogonNt40Response(byte[] netlogonBytes) {
		ByteBuffer buf = wrap(netlogonBytes);

		// Read NETLOGON_SAM_LOGON_RESPONSE_NT40 structure
		// Opcode
		this.opcode = getOpcode(buf, Opcode.LOGON_SAM_LOGON_RESPONSE);
		// UnicodeLogonServer
		this.unicodeLogonServer = getUnicodeString(buf);
		// UnicodeUserName
		this.unicodeUserName = getUnicodeString(buf);
		// UnicodeDomainName
		this.unicodeDomainName = getUnicodeString(buf);
		// NtVersion
		this.ntVersion = getNtVersion(buf, NETLOGON_NT_VERSION_1);
		// LmNtToken + Lm20Token
		consumeLmTokens(buf);
	}

	public String getUnicodeLogonServer() {
		return unicodeLogonServer;
	}

	public String getUnicodeUserName() {
		return unicodeUserName;
	}

	public String getUnicodeDomainName() {
		return unicodeDomainName;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("NetlogonSamLogonNt40Response[");
		sb.append("opcode: ").append(opcode);
		if (StringUtils.isNotEmpty(unicodeLogonServer))
			sb.append(", unicodeLogonServer: ").append(unicodeLogonServer);
		if (StringUtils.isNotEmpty(unicodeUserName))
			sb.append(", unicodeUserName: ").append(unicodeUserName);
		if (StringUtils.isNotEmpty(unicodeDomainName))
			sb.append(", unicodeDomainName: ").append(unicodeDomainName);
		sb.append(", ntVersion: ").append(IntFlag.toFlagsString(ntVersion));
		sb.append("]");
		return sb.toString();
	}
}
