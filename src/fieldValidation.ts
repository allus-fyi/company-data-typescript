/**
 * Country-data helpers.
 *
 * What a value must satisfy for its field TYPE lives in `./fieldTypes.js`: a type is a row in
 * the served registry and `FieldTypeRegistry` is the one interpreter of those rows. These two
 * helpers are about the bundled country dataset itself, which no registry row carries.
 */

import { COUNTRY_CODES, DIAL_CODES } from './countryData.js';

const COUNTRY_CODE_SET = new Set<string>(COUNTRY_CODES as readonly string[]);

/** True if `code` is an assigned ISO 3166-1 alpha-2 country code. */
export function isValidCountryCode(code: string | null | undefined): boolean {
  return code !== null && code !== undefined && COUNTRY_CODE_SET.has(code);
}

/** The ITU E.164 dial code (digits only, no `+`) for a country code, or null. */
export function dialCodeFor(code: string | null | undefined): string | null {
  if (code === null || code === undefined) return null;
  return DIAL_CODES[code] ?? null;
}
