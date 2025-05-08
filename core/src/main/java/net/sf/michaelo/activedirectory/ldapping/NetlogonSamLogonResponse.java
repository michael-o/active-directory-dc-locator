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

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

import net.sf.michaelo.activedirectory.IntFlag;
import net.sf.michaelo.activedirectory.StringUtils;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9b333971-6dd7-4003-a898-6e51b2c02110"><code>
 * NETLOGON_SAM_LOGON_RESPONSE</code></a> structure.
 */
public class NetlogonSamLogonResponse extends NetlogonSamLogonBaseResponse {

	private static final Set<NetlogonNtVersion> NETLOGON_NT_VERSION_5 =
			Collections.unmodifiableSet(EnumSet.of(NetlogonNtVersion.V1, NetlogonNtVersion.V5));

	private UUID domainGuid;
	private String unicodeLogonServer;
	private String unicodeUserName;
	private String unicodeDomainName;
	private String dnsForestName;
	private String dnsDomainName;
	private String dnsHostName;
	private InetAddress dcIpAddress;
	private Set<DsFlag> flags;

	public NetlogonSamLogonResponse(byte[] netlogonBytes) {
		ByteBuffer buf = wrap(netlogonBytes);

		// Read NETLOGON_SAM_LOGON_RESPONSE structure
		// Opcode
		this.opcode = getOpcode(buf, Opcode.LOGON_SAM_LOGON_RESPONSE);
		// UnicodeLogonServer
		this.unicodeLogonServer = getUnicodeString(buf);
		// UnicodeUserName
		this.unicodeUserName = getUnicodeString(buf);
		// UnicodeDomainName
		this.unicodeDomainName = getUnicodeString(buf);
		// DomainGuid
		this.domainGuid = getGuid(buf);
		// NullGuid
		buf.getLong();
		buf.getLong();
		// DnsForestName
		dnsForestName = getCompressedDomainName(buf);
		// DnsDomainName
		dnsDomainName = getCompressedDomainName(buf);
		// DnsHostName
		dnsHostName = getCompressedDomainName(buf);
		// DcIpAddress
		byte[] dcIpAddressBytes = new byte[4];
		// swap byte order since Windows uses little endian, but everyone else big endian
		dcIpAddressBytes[3] = buf.get();
		dcIpAddressBytes[2] = buf.get();
		dcIpAddressBytes[1] = buf.get();
		dcIpAddressBytes[0] = buf.get();
		dcIpAddress = getInetAddress(dcIpAddressBytes);
		// Flags
		this.flags = IntFlag.fromFlags(DsFlag.class, buf.getInt());
		// NtVersion
		this.ntVersion = getNtVersion(buf, NETLOGON_NT_VERSION_5);
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

	public UUID getDomainGuid() {
		return domainGuid;
	}

	public String getDnsForestName() {
		return dnsForestName;
	}

	public String getDnsDomainName() {
		return dnsDomainName;
	}

	public String getDnsHostName() {
		return dnsHostName;
	}

	public InetAddress getDcIpAddress() {
		return dcIpAddress;
	}

	public Set<DsFlag> getFlags() {
		return flags;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("NetlogonSamLogonResponse[");
		sb.append("opcode: ").append(opcode);
		if (StringUtils.isNotEmpty(unicodeLogonServer))
			sb.append(", unicodeLogonServer: ").append(unicodeLogonServer);
		if (StringUtils.isNotEmpty(unicodeUserName))
			sb.append(", unicodeUserName: ").append(unicodeUserName);
		if (StringUtils.isNotEmpty(unicodeDomainName))
			sb.append(", unicodeDomainName: ").append(unicodeDomainName);
		sb.append(", domainGuid: ").append(domainGuid);
		sb.append(", dnsForestName: ").append(dnsForestName);
		sb.append(", dnsDomainName: ").append(dnsDomainName);
		sb.append(", dnsHostName: ").append(dnsHostName);
		sb.append(", dcIpAddress: ").append(dcIpAddress.getHostAddress());
		sb.append(", flags: ").append(IntFlag.toFlagsString(flags));
		sb.append(", ntVersion: ").append(IntFlag.toFlagsString(ntVersion));
		sb.append("]");
		return sb.toString();
	}
}
