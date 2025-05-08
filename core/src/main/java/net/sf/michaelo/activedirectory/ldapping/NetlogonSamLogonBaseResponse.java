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
import java.net.UnknownHostException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;

import net.sf.michaelo.activedirectory.IntFlag;

/** Base class for all Netlogon SAM Logon structures. */
public abstract class NetlogonSamLogonBaseResponse {

	private static final Logger LOGGER = Logger.getLogger(NetlogonSamLogonBaseResponse.class.getName());

	private static final byte LABEL_NORMAL = (byte) 0;
	private static final byte LABEL_COMPRESSION = (byte) 0xC0;
	private static final byte LABEL_MASK = (byte) 0xC0;

	protected Opcode opcode;
	protected Set<NetlogonNtVersion> ntVersion;

	protected ByteBuffer wrap(byte[] netlogonBytes) {
		Objects.requireNonNull(netlogonBytes, "netlogonBytes cannot be null");
		if (netlogonBytes.length == 0) throw new IllegalArgumentException("netlogonBytes cannot be empty");

		ByteBuffer buf = ByteBuffer.wrap(netlogonBytes);
		buf.order(ByteOrder.LITTLE_ENDIAN);

		return buf;
	}

	protected Opcode getOpcode(ByteBuffer buf, Opcode expectedOpcode) {
		Opcode opcode = Opcode.fromShortValue(buf.getShort());
		if (opcode != expectedOpcode)
			throw new IllegalArgumentException("Opcode must be " + expectedOpcode + ", but is " + opcode);
		return opcode;
	}

	protected Set<NetlogonNtVersion> getNtVersion(ByteBuffer buf, Set<NetlogonNtVersion> expectedNtVersion) {
		Set<NetlogonNtVersion> ntVersion = IntFlag.fromFlags(NetlogonNtVersion.class, buf.getInt());
		if (!ntVersion.containsAll(expectedNtVersion))
			throw new IllegalArgumentException("NtVersion must contain [" + IntFlag.toFlagsString(expectedNtVersion)
					+ "], but contains [" + IntFlag.toFlagsString(ntVersion) + "]");
		return ntVersion;
	}

	protected String getUnicodeString(ByteBuffer buf) {
		if (buf.remaining() < 2)
			throw new IllegalArgumentException("Buffer has not enough bytes to read Unicode string");
		int startPos = ((Buffer) buf).position();
		int endPos = -1;
		boolean nullTerminatorFound = false;
		while (buf.hasRemaining() && !nullTerminatorFound) {
			byte low = buf.get();
			byte high = buf.get();
			endPos = ((Buffer) buf).position();
			if (low == 0x00 && high == 0x00) nullTerminatorFound = true;
		}
		if (!nullTerminatorFound) throw new IllegalArgumentException("Buffer contains unterminated Unicode string");
		byte[] strBytes = new byte[endPos - startPos];
		((Buffer) buf).position(startPos);
		buf.get(strBytes);
		if (strBytes.length == 2 && strBytes[0] == 0x00 && strBytes[1] == 0x00) return null;
		return new String(strBytes, 0, strBytes.length - 2 /* delete null */, StandardCharsets.UTF_16LE);
	}

	protected UUID getGuid(ByteBuffer buf) {
		// https://stackoverflow.com/a/28628209/696632
		ByteBuffer guidBuf = ByteBuffer.allocate(16);
		ByteOrder order = buf.order();
		buf.order(ByteOrder.LITTLE_ENDIAN);
		guidBuf.putInt(buf.getInt()).putShort(buf.getShort()).putShort(buf.getShort());
		buf.order(ByteOrder.BIG_ENDIAN);
		guidBuf.putLong(buf.getLong());
		((Buffer) guidBuf).rewind();
		buf.order(order);
		return new UUID(guidBuf.getLong(), guidBuf.getLong());
	}

	protected String getCompressedDomainName(ByteBuffer buf) {
		boolean done = false;
		boolean pointerMode = false;
		List<String> labels = new ArrayList<>();
		int currPos = ((Buffer) buf).position();
		while (buf.hasRemaining() && !done) {
			byte len = buf.get();
			if (!pointerMode) currPos++;
			switch (len & LABEL_MASK) {
				case LABEL_NORMAL:
					if (len == 0) {
						done = true;
					} else {
						if (len > buf.remaining())
							throw new IllegalArgumentException(String.format(
									"Domain label longer (%d) than bytes in buffer (%d)", len, buf.remaining()));
						byte[] labelBytes = new byte[len];
						buf.get(labelBytes);
						labels.add(new String(labelBytes, StandardCharsets.UTF_8));
						if (!pointerMode) currPos += len;
					}
					break;
				case LABEL_COMPRESSION:
					short offset = (short) ((len & ~LABEL_COMPRESSION) << 8 | buf.get() & 0xFF);
					if (!pointerMode) currPos++;
					// position of pointer minus two length bytes
					int maxOffset = currPos - 2;
					if (offset >= maxOffset)
						throw new IllegalArgumentException(String.format(
								"Domain name pointer offset (%d) beyond current position (%d)", offset, maxOffset));
					((Buffer) buf).position(offset);
					pointerMode = true;
					break;
				default:
					throw new IllegalArgumentException(String.format("Invalid domain name label type: 0x%02X", len));
			}
		}
		((Buffer) buf).position(currPos);

		if (labels.isEmpty()) return null;

		return String.join(".", labels);
	}

	protected InetAddress getInetAddress(byte[] addressBytes) {
		try {
			return InetAddress.getByAddress(addressBytes);
		} catch (UnknownHostException e) {
			LOGGER.fine(() ->
					String.format("Failed to convert address bytes %s to InetAddress", Arrays.toString(addressBytes)));
			return null;
		}
	}

	protected void consumeLmTokens(ByteBuffer buf) {
		short lmNtToken = buf.getShort();
		if ((lmNtToken & 0xFFFF) == 0)
			throw new IllegalArgumentException(String.format("LmNtToken must be 0xFFFF, but is 0x%04X", lmNtToken));
		short lm20Token = buf.getShort();
		if ((lm20Token & 0xFFFF) == 0)
			throw new IllegalArgumentException(String.format("Lm20Token must be 0xFFFF, but is 0x%04X", lm20Token));
	}

	public Opcode getOpcode() {
		return opcode;
	}

	public Set<NetlogonNtVersion> getNtVersion() {
		return ntVersion;
	}
}
