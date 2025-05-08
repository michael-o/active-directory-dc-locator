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

import java.util.HashMap;
import java.util.Map;

/**
 * A class representing the <a href=
 * "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/07133ff2-a9a3-4aa9-8896-a7dcb53bdfe9">operation
 * code</a>.
 */
public enum Opcode {
	LOGON_SAM_LOGON_RESPONSE((short) 19),
	LOGON_SAM_LOGON_RESPONSE_EX((short) 23);

	private static final Map<Short, Opcode> MAPPING = new HashMap<>();

	static {
		for (Opcode opcode : values()) {
			MAPPING.put(opcode.shortValue(), opcode);
		}
	}

	private final short shortValue;

	Opcode(short shortValue) {
		this.shortValue = shortValue;
	}

	public short shortValue() {
		return shortValue;
	}

	public static Opcode fromShortValue(short shortValue) {
		Opcode opcode = MAPPING.get(shortValue);
		if (opcode == null) throw new IllegalArgumentException("Invalid value: " + shortValue);

		return opcode;
	}
}
