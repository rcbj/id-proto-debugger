// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: xacml_datatypes.js
//
// ---------------------------------------------------------------------------
// THE SEVENTEEN DATATYPES: HOW A LEXICAL FORM BECOMES A VALUE, WHEN TWO VALUES
// ARE EQUAL, AND HOW THEY ORDER.
//
// `xacml_functions.js` is generated over the table in here, which is why this
// file exists separately: 210 of XACML's function identifiers are the same
// twenty-odd operations parameterised by type — `string-is-in`,
// `integer-is-in`, `date-is-in` and eleven more are one function and a table
// row each. Writing them out by hand would be 210 chances to paste the wrong
// comparison into one of them, and the one that got it wrong would be the one
// nobody had a test for.
//
// So a row here is the whole of what a type is, and every function in the
// library reaches it through this table rather than knowing anything about
// types itself.
//
// ---------------------------------------------------------------------------
// FIVE PLACES WHERE "EQUAL" IS NOT STRING EQUALITY, AND EACH OF THEM IS A
// DEFECT THAT LOOKS LIKE A WORKING IMPLEMENTATION.
//
//   1. `integer` IS UNBOUNDED. xs:integer has no upper limit and JavaScript's
//      Number silently loses precision above 2^53, so an integer here is a
//      BigInt. A policy comparing two account numbers or two large identifiers
//      would otherwise find them equal because both rounded to the same
//      double — a permit granted on a comparison that never happened.
//   2. `double` HAS THREE VALUES STRING EQUALITY GETS WRONG, AND ONE WHERE
//      IEEE 754 IS THE WRONG ANSWER. `INF`, `-INF` and `NaN` are legal
//      xs:double lexical forms that `parseFloat` does not accept. And
//      **NaN EQUALS NaN here**: XML Schema defines equality over a value space
//      holding exactly one NaN, XACML A.3.4 defers to XML Schema, so
//      `double-equal(NaN, NaN)` is True — the opposite of `a === b`, and of
//      what anybody who has met floating point expects. See the row itself.
//   3. `rfc822Name` IS HALF CASE-INSENSITIVE. The domain part is compared
//      case-insensitively and the local part is NOT (section A.3.14), so
//      `Bob@example.com` and `bob@example.com` are DIFFERENT addresses while
//      `bob@EXAMPLE.COM` and `bob@example.com` are the same one. Lower-casing
//      the whole string is the obvious implementation and it is wrong in the
//      direction that grants access.
//   4. `x500Name` IS AN RFC 2253 DISTINGUISHED NAME, not a string. Equality is
//      over the parsed RDN sequence with the attribute types compared
//      case-insensitively, so `CN=bob,O=Acme` equals `cn=bob, o=Acme` and does
//      not equal `O=Acme,CN=bob` — the order of RDNs is significant.
//   5. `anyURI` IS COMPARED AS A STRING AND THAT IS THE SURPRISE. It looks
//      like the type that would want normalisation — case-folding a scheme,
//      resolving `..`, adding a trailing slash — and section A.3.3 says plain
//      string equality on the lexical form. An implementation that helpfully
//      normalised would make two different resources into one.
//
// ---------------------------------------------------------------------------
// DATES AND TIMES CARRY THEIR TIMEZONE'S PRESENCE, NOT JUST ITS VALUE.
//
// A `dateTime` with no timezone is not a `dateTime` in UTC — it is a value
// whose timezone is unknown, and XML Schema orders it against a value that HAS
// one only when the answer is the same for every timezone in [-14:00, +14:00].
// So a parsed value here keeps `tz: null` distinct from `tz: 0`, and
// `compare()` reports `null` for a genuinely indeterminate ordering rather
// than picking one. A representation that defaulted a missing timezone to UTC
// would answer every comparison, and would answer some of them wrongly with no
// way for anything downstream to know.
// ---------------------------------------------------------------------------

const { log } = require('../xacml_runtime');
const ownMembers = require('./xacml_own_members');
const model = require('./xacml_model');

const TYPE = model.TYPE;

// ---------------------------------------------------------------------------
// SMALL SHARED PARSING HELPERS.
// ---------------------------------------------------------------------------

// XML Schema allows leading and trailing whitespace on every lexical form, and
// collapses internal whitespace for some. Every parser below trims; none of
// them collapses, because none of these types permits internal whitespace.
function trimmed(text) {
  log.debug("Entering trimmed().");
  log.debug("Leaving trimmed().");
  return String(text === null || text === undefined ? '' : text).trim();
}

function fail(type, lexical) {
  log.debug("Entering fail().");
  log.debug("Leaving fail().");
  return model.syntaxError('"' + lexical + '" is not a valid ' + type + '.',
                           { type: type, lexical: lexical });
}

// ---------------------------------------------------------------------------
// DATE AND TIME.
//
// One parser for all three, because xs:date, xs:time and xs:dateTime are three
// slices of one grammar and three regular expressions would be three places
// for the timezone half to drift apart.
//
// The year may be negative and may have more than four digits; the seconds may
// be fractional. Both are xs:dateTime's own rules and both are easy to leave
// out — a four-digit-only year regex rejects a valid document, which reads as
// a policy defect rather than as a parser defect.
// ---------------------------------------------------------------------------
const DATE_PART = '(-?\\d{4,})-(\\d{2})-(\\d{2})';
const TIME_PART = '(\\d{2}):(\\d{2}):(\\d{2}(?:\\.\\d+)?)';
const TZ_PART = '(Z|[+-]\\d{2}:\\d{2})?';

const DATE_RE = new RegExp('^' + DATE_PART + TZ_PART + '$');
const TIME_RE = new RegExp('^' + TIME_PART + TZ_PART + '$');
const DATETIME_RE = new RegExp('^' + DATE_PART + 'T' + TIME_PART +
                               TZ_PART + '$');

// Minutes east of UTC, or null when the value carries no timezone at all —
// which is a different fact from "+00:00" and is kept as one.
function timezoneMinutes(text) {
  log.debug("Entering timezoneMinutes().");
  if (!text) {
    log.debug("Leaving timezoneMinutes().");
    return null;
  }
  if (text === 'Z') {
    log.debug("Leaving timezoneMinutes().");
    return 0;
  }
  const sign = text[0] === '-' ? -1 : 1;
  const hours = parseInt(text.slice(1, 3), 10);
  const minutes = parseInt(text.slice(4, 6), 10);
  // XML Schema Part 2, 3.2.7.3: a timezone is -14:00 to +14:00, and its
  // minutes are 00-59. NaN is returned for anything outside, and every
  // caller refuses a NaN offset. Accepted until 2026-11-13.
  if (minutes > 59 || hours * 60 + minutes > 14 * 60) {
    log.debug("Leaving timezoneMinutes(). Out of range.");
    return NaN;
  }
  log.debug("Leaving timezoneMinutes().");
  return sign * (hours * 60 + minutes);
}

/**
 * Writes a timezone offset in minutes back as its lexical form.
 *
 * An absent offset gives the empty string and zero gives `Z`; anything else
 * is `+HH:MM` or `-HH:MM`.
 * @param minutes - the offset from UTC in minutes, or null for none
 * @returns the lexical timezone suffix
 */
function timezoneText(minutes) {
  log.debug("Entering timezoneText().");
  if (minutes === null || minutes === undefined) {
    log.debug("Leaving timezoneText().");
    return '';
  }
  if (minutes === 0) {
    log.debug("Leaving timezoneText().");
    return 'Z';
  }
  const sign = minutes < 0 ? '-' : '+';
  const absolute = Math.abs(minutes);
  log.debug("Leaving timezoneText().");
  return sign + pad2(Math.floor(absolute / 60)) + ':' + pad2(absolute % 60);
}

function pad2(value) {
  log.debug("Entering pad2().");
  log.debug("Leaving pad2().");
  return (value < 10 ? '0' : '') + value;
}

// Days since 1970-01-01 for a proleptic Gregorian date, computed rather than
// taken from `Date`, because `Date` cannot represent years outside roughly
// ±275760 and silently clamps, and because it applies a local timezone this
// code has taken care to keep out.
/**
 * Counts the days from 1970-01-01 to a proleptic Gregorian date.
 *
 * Computed rather than taken from `Date`, which clamps far years and applies
 * a local timezone.
 * @param year - the year, which may be negative
 * @param month - the month, 1 to 12
 * @param day - the day of the month
 * @returns the number of days since the epoch, negative before it
 */
function daysFromCivil(year, month, day) {
  log.debug("Entering daysFromCivil().");
  const y = year - (month <= 2 ? 1 : 0);
  const era = Math.floor((y >= 0 ? y : y - 399) / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) +
              day - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  log.debug("Leaving daysFromCivil().");
  return era * 146097 + doe - 719468;
}

// The number of days in `month` of the proleptic Gregorian `year`. Year 0
// exists in XML Schema 1.1's reading (1 BCE) and is a leap year, which the
// arithmetic below gives without a special case.
function daysInMonthOf(year, month) {
  log.debug("Entering daysInMonthOf().");
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  log.debug("Leaving daysInMonthOf().");
  return days[month - 1];
}

function parseDateTimeish(lexical, shape) {
  log.debug("Entering parseDateTimeish().");
  const text = trimmed(lexical);
  let match = null;
  if (shape === 'date') {
    match = DATE_RE.exec(text);
  } else if (shape === 'time') {
    match = TIME_RE.exec(text);
  } else {
    match = DATETIME_RE.exec(text);
  }
  if (!match) {
    log.debug("Leaving parseDateTimeish().");
    return null;
  }
  let year = 1970;
  let month = 1;
  let day = 1;
  let hour = 0;
  let minute = 0;
  let second = 0;
  let tz = null;
  if (shape === 'date') {
    year = parseInt(match[1], 10);
    month = parseInt(match[2], 10);
    day = parseInt(match[3], 10);
    tz = timezoneMinutes(match[4]);
  } else if (shape === 'time') {
    hour = parseInt(match[1], 10);
    minute = parseInt(match[2], 10);
    second = parseFloat(match[3]);
    tz = timezoneMinutes(match[4]);
  } else {
    year = parseInt(match[1], 10);
    month = parseInt(match[2], 10);
    day = parseInt(match[3], 10);
    hour = parseInt(match[4], 10);
    minute = parseInt(match[5], 10);
    second = parseFloat(match[6]);
    tz = timezoneMinutes(match[7]);
  }
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 24 ||
      minute > 59 || second >= 61 || Number.isNaN(tz)) {
    log.debug("Leaving parseDateTimeish().");
    return null;
  }
  // XML Schema Part 2, D.2 / 3.2.7.1: the day must exist in its month
  // ("Day-of-month Values"), so 2021-02-29 and 2020-02-30 are not dates; and
  // hour 24 is allowed only as 24:00:00, the end of a day. Both were accepted
  // until 2026-11-13, which made a policy's misspelt literal an ordinary
  // value rather than the processing error it is.
  if (shape !== 'time' && day > daysInMonthOf(year, month)) {
    log.debug("Leaving parseDateTimeish(). No such day in that month.");
    return null;
  }
  if (hour === 24 && (minute !== 0 || second !== 0)) {
    log.debug("Leaving parseDateTimeish(). Hour 24 is only 24:00:00.");
    return null;
  }
  log.debug("Leaving parseDateTimeish().");
  return { shape: shape, year: year, month: month, day: day, hour: hour,
           minute: minute, second: second, tz: tz };
}

// Seconds from an epoch, in the value's own timezone offset applied. For a
// `time` the date part is fixed, which is correct: xs:time compares two times
// of day and has no date to disagree about.
/**
 * Converts a parsed date, time or dateTime to seconds from the epoch in UTC.
 *
 * A `time` has no date part and is counted from the start of the day.
 * @param value - a parsed temporal value (shape, fields and `tz`)
 * @param assumedTz - the offset in minutes to use when the value has none
 * @returns the instant in seconds
 */
function instantSeconds(value, assumedTz) {
  log.debug("Entering instantSeconds().");
  const tz = value.tz === null ? assumedTz : value.tz;
  let seconds = 0;
  if (value.shape !== 'time') {
    seconds += daysFromCivil(value.year, value.month, value.day) * 86400;
  }
  seconds += value.hour * 3600 + value.minute * 60 + value.second;
  log.debug("Leaving instantSeconds().");
  return seconds - tz * 60;
}

// ---------------------------------------------------------------------------
// THE ORDER RELATION XML SCHEMA ACTUALLY DEFINES, AND WHY IT CAN ANSWER
// "I DO NOT KNOW".
//
// Two values that both carry a timezone, or both carry none, compare
// ordinarily. A value WITH one against a value WITHOUT one is compared against
// the whole range the missing timezone could be — [-14:00, +14:00] — and the
// comparison holds only if it holds at both ends. Where it does not, XML
// Schema says the two are INCOMPARABLE, and this function returns null for it.
//
// Returning null rather than 0 is the point. `0` would mean "equal", so a
// `date-less-than` on two incomparable values would answer `false`, which is a
// claim about the world. Null propagates to Indeterminate, which is the
// truthful answer.
// ---------------------------------------------------------------------------
/**
 * Orders two temporal values as XML Schema defines, or says they are
 * incomparable.
 *
 * When only one carries a timezone the comparison must hold across the whole
 * [-14:00, +14:00] range; where it does not the answer is null, which the
 * caller turns into Indeterminate rather than a false.
 * @param left - the first parsed temporal value
 * @param right - the second parsed temporal value
 * @returns -1, 0 or 1, or null when the two are incomparable
 */
function compareTemporal(left, right) {
  log.debug('Entering compareTemporal().');
  const bothKnown = left.tz !== null && right.tz !== null;
  const bothUnknown = left.tz === null && right.tz === null;
  if (bothKnown || bothUnknown) {
    const a = instantSeconds(left, 0);
    const b = instantSeconds(right, 0);
    log.debug('Leaving compareTemporal(). Directly comparable.');
    return a < b ? -1 : (a > b ? 1 : 0);
  }
  // One of them has no timezone. Compare at both ends of the permitted range;
  // agree or admit ignorance.
  const low = instantSeconds(left, left.tz === null ? 14 * 60 : left.tz);
  const lowRight = instantSeconds(right, right.tz === null ? 14 * 60
                                                           : right.tz);
  const high = instantSeconds(left, left.tz === null ? -14 * 60 : left.tz);
  const highRight = instantSeconds(right, right.tz === null ? -14 * 60
                                                            : right.tz);
  const first = low < lowRight ? -1 : (low > lowRight ? 1 : 0);
  const second = high < highRight ? -1 : (high > highRight ? 1 : 0);
  if (first === second) {
    log.debug('Leaving compareTemporal(). Same at both ends of the range.');
    return first;
  }
  log.debug('Leaving compareTemporal(). Incomparable — timezone unknown.');
  return null;
}

// ---------------------------------------------------------------------------
// DURATIONS.
//
// Two types, and they are deliberately NOT one. A yearMonthDuration counts
// months and a dayTimeDuration counts seconds, and they are incomparable to
// each other because a month is not a fixed number of days. XACML keeps them
// apart for that reason and so does this file — a single `duration` type with
// both fields would invite exactly the comparison the split exists to prevent.
// ---------------------------------------------------------------------------
const YEARMONTH_RE = /^(-?)P(?:(\d+)Y)?(?:(\d+)M)?$/;
const DAYTIME_RE =
  /^(-?)P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/;

function parseYearMonthDuration(lexical) {
  log.debug("Entering parseYearMonthDuration().");
  const text = trimmed(lexical);
  const match = YEARMONTH_RE.exec(text);
  if (!match || (match[2] === undefined && match[3] === undefined)) {
    log.debug("Leaving parseYearMonthDuration().");
    return null;
  }
  const months = (parseInt(match[2] || '0', 10) * 12) +
                 parseInt(match[3] || '0', 10);
  log.debug("Leaving parseYearMonthDuration().");
  return { months: match[1] === '-' ? -months : months };
}

function parseDayTimeDuration(lexical) {
  log.debug("Entering parseDayTimeDuration().");
  const text = trimmed(lexical);
  const match = DAYTIME_RE.exec(text);
  if (!match) {
    log.debug("Leaving parseDayTimeDuration().");
    return null;
  }
  if (match[2] === undefined && match[3] === undefined &&
      match[4] === undefined && match[5] === undefined) {
    log.debug("Leaving parseDayTimeDuration().");
    return null;
  }
  // A `T` with nothing after it is not a valid duration, and the regular
  // expression above accepts it — checked here rather than by making the
  // pattern harder to read.
  if (/T$/.test(text)) {
    log.debug("Leaving parseDayTimeDuration().");
    return null;
  }
  const seconds = parseInt(match[2] || '0', 10) * 86400 +
                  parseInt(match[3] || '0', 10) * 3600 +
                  parseInt(match[4] || '0', 10) * 60 +
                  parseFloat(match[5] || '0');
  log.debug("Leaving parseDayTimeDuration().");
  return { seconds: match[1] === '-' ? -seconds : seconds };
}

// ---------------------------------------------------------------------------
// RFC822 NAME. See defect 3 in the header — the domain folds and the local
// part does not.
// ---------------------------------------------------------------------------
function parseRfc822Name(lexical) {
  log.debug("Entering parseRfc822Name().");
  const text = trimmed(lexical);
  const at = text.lastIndexOf('@');
  if (at <= 0 || at === text.length - 1) {
    log.debug("Leaving parseRfc822Name().");
    return null;
  }
  const domain = text.slice(at + 1);
  // A domain with no dot is legal in the grammar; a domain with whitespace or
  // an underscore is not, and one of the conformance cases carries an
  // underscore precisely because the original suite had it wrong.
  if (/[\s@]/.test(domain) || /[\s@]/.test(text.slice(0, at))) {
    log.debug("Leaving parseRfc822Name().");
    return null;
  }
  log.debug("Leaving parseRfc822Name().");
  return { local: text.slice(0, at), domain: domain.toLowerCase() };
}

// ---------------------------------------------------------------------------
// X.500 NAME. RFC 2253, parsed far enough to compare — which is further than
// it looks, because the escaping rules mean a comma inside a value is not a
// separator.
// ---------------------------------------------------------------------------
function parseX500Name(lexical) {
  log.debug("Entering parseX500Name().");
  const text = trimmed(lexical);
  if (!text) {
    log.debug("Leaving parseX500Name().");
    return null;
  }
  const rdns = [];
  let current = '';
  let escaped = false;
  let quoted = false;
  const parts = [];
  for (let i = 0; i < text.length; i += 1) {
    const character = text[i];
    if (escaped) {
      current += character;
      escaped = false;
    } else if (character === '\\') {
      current += character;
      escaped = true;
    } else if (character === '"') {
      quoted = !quoted;
      current += character;
    } else if (character === ',' && !quoted) {
      parts.push(current);
      current = '';
    } else {
      current += character;
    }
  }
  parts.push(current);
  for (let i = 0; i < parts.length; i += 1) {
    const piece = parts[i].trim();
    const equals = piece.indexOf('=');
    if (equals <= 0) {
      log.debug("Leaving parseX500Name().");
      return null;
    }
    rdns.push({ attribute: piece.slice(0, equals).trim().toLowerCase(),
                value: piece.slice(equals + 1).trim() });
  }
  log.debug("Leaving parseX500Name().");
  return { rdns: rdns };
}

function x500Equal(left, right) {
  log.debug("Entering x500Equal().");
  if (left.rdns.length !== right.rdns.length) {
    log.debug("Leaving x500Equal().");
    return false;
  }
  for (let i = 0; i < left.rdns.length; i += 1) {
    if (left.rdns[i].attribute !== right.rdns[i].attribute) {
      log.debug("Leaving x500Equal().");
      return false;
    }
    // The VALUE is compared case-insensitively too, which is what X.500's
    // caseIgnoreMatch does for the string attribute types that make up
    // essentially every DN anybody writes. Doing it case-sensitively would
    // make `CN=Bob` and `cn=bob` two different people.
    if (left.rdns[i].value.toLowerCase() !== right.rdns[i].value
                                                  .toLowerCase()) {
      log.debug("Leaving x500Equal().");
      return false;
    }
  }
  log.debug("Leaving x500Equal().");
  return true;
}

// ---------------------------------------------------------------------------
// DNS NAME and IP ADDRESS. Both carry an optional port range, and the
// ipAddress additionally an optional mask; both are compared on their parsed
// parts rather than as strings, so `192.168.1.1:80-90` and the same address
// written with the same parts are equal whatever the spacing.
// ---------------------------------------------------------------------------
function parsePortRange(text) {
  log.debug("Entering parsePortRange().");
  if (text === undefined || text === '') {
    log.debug("Leaving parsePortRange(). None.");
    return { low: null, high: null };
  }
  // portrange = portnumber | "-"portnumber | portnumber"-"[portnumber],
  // each portnumber decimal. A bare "-" or a non-digit is refused.
  const match = /^(\d*)(-?)(\d*)$/.exec(text);
  if (!match || (match[1] === '' && match[3] === '') ||
      (match[2] === '' && match[3] !== '')) {
    log.debug("Leaving parsePortRange(). Malformed.");
    return null;
  }
  const low = match[1] === '' ? null : parseInt(match[1], 10);
  if (match[2] === '') {
    log.debug("Leaving parsePortRange(). One port.");
    return { low: low, high: low };
  }
  log.debug("Leaving parsePortRange(). A range.");
  return { low: low, high: match[3] === '' ? null : parseInt(match[3], 10) };
}

// RFC 2396 3.2.2 hostname, with XACML's left-most wildcard.
//   hostname    = *( domainlabel "." ) toplabel [ "." ]
//   domainlabel = alphanum | alphanum *( alphanum | "-" ) alphanum
//   toplabel    = alpha | alpha *( alphanum | "-" ) alphanum
function isRfc2396Hostname(host) {
  log.debug("Entering isRfc2396Hostname().");
  const labels = host.replace(/\.$/, '').split('.');
  const domainLabel = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;
  const topLabel = /^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;
  const ok = labels.every(function (label, index) {
    if (index === 0 && label === '*') {
      return labels.length > 1;
    }
    return index === labels.length - 1 ? topLabel.test(label) :
      domainLabel.test(label);
  });
  log.debug("Leaving isRfc2396Hostname(). " + ok);
  return ok;
}

// RFC 2396 3.2.2 IPv4address = 1*digit "." 1*digit "." 1*digit "." 1*digit,
// which is the syntax XACML B.4 names for an IPv4 address or mask. It is a
// SYNTAX: RFC 2396 does not bound an octet, so neither does this.
function isRfc2396Ipv4(text) {
  log.debug("Entering isRfc2396Ipv4().");
  const ok = /^\d+\.\d+\.\d+\.\d+$/.test(text);
  log.debug("Leaving isRfc2396Ipv4(). " + ok);
  return ok;
}

// The inside of an RFC 2732 ipv6reference: hex groups and colons, with at
// most one "::" and an optional trailing dotted IPv4 part.
function isIpv6Literal(text) {
  log.debug("Entering isIpv6Literal().");
  let ok = /^[0-9A-Fa-f:.]+$/.test(text) && text.indexOf(':') >= 0 &&
    (text.match(/::/g) || []).length <= 1;
  if (ok) {
    const groups = text.split(':');
    const last = groups[groups.length - 1];
    if (last.indexOf('.') >= 0) {
      ok = isRfc2396Ipv4(last);
      groups.pop();
    }
    ok = ok && groups.every(function (group) {
      return group === '' || /^[0-9A-Fa-f]{1,4}$/.test(group);
    });
  }
  log.debug("Leaving isIpv6Literal(). " + ok);
  return ok;
}

function parseDnsName(lexical) {
  log.debug("Entering parseDnsName().");
  const text = trimmed(lexical);
  const colon = text.indexOf(':');
  const host = colon < 0 ? text : text.slice(0, colon);
  // B.4 / 10.2.x: the hostname follows RFC 2396 section 3.2.2 — labels of
  // letters, digits and interior hyphens, a top label that begins with a
  // letter, an optional trailing dot — "except that a wildcard '*' may be
  // used in the left-most component". Anything else is refused; until
  // 2026-11-13 any text without whitespace was a dnsName.
  if (!host || !isRfc2396Hostname(host)) {
    log.debug("Leaving parseDnsName().");
    return null;
  }
  const ports = parsePortRange(colon < 0 ? '' : text.slice(colon + 1));
  if (!ports) {
    log.debug("Leaving parseDnsName().");
    return null;
  }
  log.debug("Leaving parseDnsName().");
  // The hostname is case-insensitive; the port range is numeric.
  return { host: host.toLowerCase(), ports: ports };
}

function parseIpAddress(lexical) {
  log.debug("Entering parseIpAddress().");
  const text = trimmed(lexical);
  // B.4: ipAddress = address [ "/" mask ] [ ":" [ portrange ] ], where an
  // IPv4 address and mask are RFC 2396 IPv4address and an IPv6 address and
  // mask are RFC 2732 ipv6reference — BRACKETED, which is what makes their
  // colons distinguishable from the port separator's. Getting that wrong
  // turns `[::1]:80` into a host of `[`, and until 2026-11-13 a bracketed
  // MASK was not read at all, so `[a]/[m]:80` lost both mask and port.
  const v6 = /^\[([^\]]*)\](?:\/\[([^\]]*)\])?(?::(.*))?$/.exec(text);
  const v4 = /^([^/:]*)(?:\/([^:]*))?(?::(.*))?$/.exec(text);
  let address = null;
  let mask = null;
  let portText = '';
  if (text[0] === '[') {
    if (!v6 || !isIpv6Literal(v6[1]) ||
        (v6[2] !== undefined && !isIpv6Literal(v6[2]))) {
      log.debug("Leaving parseIpAddress(). Not an IPv6 reference.");
      return null;
    }
    address = v6[1];
    mask = v6[2] === undefined ? null : v6[2].toLowerCase();
    portText = v6[3] || '';
  } else {
    if (!v4 || !isRfc2396Ipv4(v4[1]) ||
        (v4[2] !== undefined && !isRfc2396Ipv4(v4[2]))) {
      log.debug("Leaving parseIpAddress(). Not an IPv4 address.");
      return null;
    }
    address = v4[1];
    mask = v4[2] === undefined ? null : v4[2];
    portText = v4[3] || '';
  }
  const ports = parsePortRange(portText);
  if (!ports) {
    log.debug("Leaving parseIpAddress(). Bad port range.");
    return null;
  }
  log.debug("Leaving parseIpAddress().");
  return { address: address.toLowerCase(), mask: mask, ports: ports };
}

function portsEqual(left, right) {
  log.debug("Entering portsEqual().");
  log.debug("Leaving portsEqual().");
  return left.low === right.low && left.high === right.high;
}

// ---------------------------------------------------------------------------
// THE TABLE.
//
// Every row carries: how to parse a lexical form, how to write one back, how
// to test equality, and — for the types that have one — how to order. A type
// with no `compare` has no ordering functions in the library, which is how
// `boolean-greater-than` fails to exist rather than existing and being wrong.
// ---------------------------------------------------------------------------
/**
 * The datatype table, keyed by datatype URI.
 *
 * Each row holds the type's `name` and `uri` and its `parse`, `write`,
 * `equal` and, for ordered types, `compare` functions.
 */
const TYPES = {};

function define(uri, row) {
  log.debug("Entering define().");
  row.uri = uri;
  TYPES[uri] = row;
  log.debug("Leaving define().");
}

define(TYPE.STRING, {
  name: 'string',
  parse: function (lexical) {
    log.debug("Entering parse().");
    log.debug("Leaving parse().");
    // NOT trimmed. xs:string preserves whitespace, and the conformance suite
    // has a case that turns on it — `string-normalize-space` would have
    // nothing to do if the parser had already done it.
    return String(lexical === null || lexical === undefined ? '' : lexical);
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return value;
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a === b;
  },
  compare: function (a, b) {
    log.debug("Entering compare().");
    log.debug("Leaving compare().");
    return a < b ? -1 : (a > b ? 1 : 0);
  }
});

define(TYPE.BOOLEAN, {
  name: 'boolean',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const text = trimmed(lexical);
    if (text === 'true' || text === '1') {
      log.debug("Leaving parse().");
      return true;
    }
    if (text === 'false' || text === '0') {
      log.debug("Leaving parse().");
      return false;
    }
    log.debug("Leaving parse().");
    throw fail('boolean', lexical);
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return value ? 'true' : 'false';
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a === b;
  }
});

define(TYPE.INTEGER, {
  name: 'integer',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const text = trimmed(lexical);
    if (!/^[+-]?\d+$/.test(text)) {
      throw fail('integer', lexical);
    }
    log.debug("Leaving parse().");
    // BigInt — see defect 1 in the header.
    return BigInt(text);
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return value.toString();
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a === b;
  },
  compare: function (a, b) {
    log.debug("Entering compare().");
    log.debug("Leaving compare().");
    return a < b ? -1 : (a > b ? 1 : 0);
  }
});

define(TYPE.DOUBLE, {
  name: 'double',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const text = trimmed(lexical);
    if (text === 'INF' || text === '+INF') {
      log.debug("Leaving parse().");
      return Infinity;
    }
    if (text === '-INF') {
      log.debug("Leaving parse().");
      return -Infinity;
    }
    if (text === 'NaN') {
      log.debug("Leaving parse().");
      return NaN;
    }
    if (!/^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$/.test(text)) {
      throw fail('double', lexical);
    }
    log.debug("Leaving parse().");
    return parseFloat(text);
  },
  write: function (value) {
    log.debug("Entering write().");
    if (value === Infinity) {
      log.debug("Leaving write().");
      return 'INF';
    }
    if (value === -Infinity) {
      log.debug("Leaving write().");
      return '-INF';
    }
    if (isNaN(value)) {
      log.debug("Leaving write().");
      return 'NaN';
    }
    // xs:double's canonical form always carries a decimal point or an
    // exponent, so an integral double is `1.0` rather than `1` — which is what
    // a conformance Response is compared against.
    if (Number.isInteger(value) && Math.abs(value) < 1e21) {
      log.debug("Leaving write().");
      return value.toFixed(1);
    }
    log.debug("Leaving write().");
    return String(value);
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    // NaN EQUALS NaN HERE, AND THAT IS NOT A BUG — it is the whole difference
    // between IEEE 754 and XML Schema, and this file had it the IEEE way until
    // the conformance suite said otherwise.
    //
    // IEEE 754 says NaN compares unequal to everything including itself, which
    // is what `a === b` gives and what every programmer expects. XML Schema
    // defines xs:double's equality over its VALUE SPACE, which holds exactly
    // one NaN — so two NaNs are the same value and are equal. XACML A.3.4
    // defers to XML Schema, so `double-equal(NaN, NaN)` is True.
    //
    // Cases IIC350 and IIC358 exist for precisely this and expect Permit. An
    // implementation that reasons from IEEE 754 — as this one did — returns
    // NotApplicable and looks completely correct while doing it.
    //
    // `-0 === 0` is true and that agrees with XML Schema, so it is left alone.
    if (isNaN(a) && isNaN(b)) {
      log.debug("Leaving equal().");
      return true;
    }
    log.debug("Leaving equal().");
    return a === b;
  },
  compare: function (a, b) {
    log.debug("Entering compare().");
    if (isNaN(a) || isNaN(b)) {
      log.debug("Leaving compare().");
      return null;
    }
    log.debug("Leaving compare().");
    return a < b ? -1 : (a > b ? 1 : 0);
  }
});

define(TYPE.ANYURI, {
  name: 'anyURI',
  // See defect 5 in the header: string equality, no normalisation.
  parse: function (lexical) {
    log.debug("Entering parse().");
    log.debug("Leaving parse().");
    return trimmed(lexical);
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return value;
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a === b;
  }
});

define(TYPE.HEXBINARY, {
  name: 'hexBinary',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const text = trimmed(lexical);
    if (text.length % 2 !== 0 || /[^0-9a-fA-F]/.test(text)) {
      throw fail('hexBinary', lexical);
    }
    log.debug("Leaving parse().");
    // Upper-cased on the way in, because hexBinary's canonical form is upper
    // case and its equality is over the OCTETS rather than the spelling —
    // `ff` and `FF` are one value.
    return text.toUpperCase();
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return value;
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a === b;
  }
});

define(TYPE.BASE64BINARY, {
  name: 'base64Binary',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const text = trimmed(lexical).replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) {
      throw fail('base64Binary', lexical);
    }
    log.debug("Leaving parse().");
    // Compared as OCTETS rather than as text, because two different base64
    // spellings can decode to the same bytes. Held as the decoded hex so that
    // equality is octet equality by construction.
    return Buffer.from(text, 'base64').toString('hex');
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return Buffer.from(value, 'hex').toString('base64');
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a === b;
  }
});

define(TYPE.DATE, {
  name: 'date',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const parsed = parseDateTimeish(lexical, 'date');
    if (!parsed) {
      throw fail('date', lexical);
    }
    log.debug("Leaving parse().");
    return parsed;
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return String(value.year).padStart(4, '0') + '-' + pad2(value.month) +
           '-' + pad2(value.day) + timezoneText(value.tz);
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return compareTemporal(a, b) === 0;
  },
  compare: compareTemporal
});

define(TYPE.TIME, {
  name: 'time',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const parsed = parseDateTimeish(lexical, 'time');
    if (!parsed) {
      throw fail('time', lexical);
    }
    log.debug("Leaving parse().");
    return parsed;
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return pad2(value.hour) + ':' + pad2(value.minute) + ':' +
           (value.second < 10 ? '0' : '') + value.second +
           timezoneText(value.tz);
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return compareTemporal(a, b) === 0;
  },
  compare: compareTemporal
});

define(TYPE.DATETIME, {
  name: 'dateTime',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const parsed = parseDateTimeish(lexical, 'dateTime');
    if (!parsed) {
      throw fail('dateTime', lexical);
    }
    log.debug("Leaving parse().");
    return parsed;
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return String(value.year).padStart(4, '0') + '-' + pad2(value.month) +
           '-' + pad2(value.day) + 'T' + pad2(value.hour) + ':' +
           pad2(value.minute) + ':' + (value.second < 10 ? '0' : '') +
           value.second + timezoneText(value.tz);
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return compareTemporal(a, b) === 0;
  },
  compare: compareTemporal
});

define(TYPE.YEARMONTH_DURATION, {
  name: 'yearMonthDuration',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const parsed = parseYearMonthDuration(lexical);
    if (!parsed) {
      throw fail('yearMonthDuration', lexical);
    }
    log.debug("Leaving parse().");
    return parsed;
  },
  write: function (value) {
    log.debug("Entering write().");
    const negative = value.months < 0;
    const months = Math.abs(value.months);
    log.debug("Leaving write().");
    return (negative ? '-' : '') + 'P' + Math.floor(months / 12) + 'Y' +
           (months % 12) + 'M';
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a.months === b.months;
  },
  compare: function (a, b) {
    log.debug("Entering compare().");
    log.debug("Leaving compare().");
    return a.months < b.months ? -1 : (a.months > b.months ? 1 : 0);
  }
});

define(TYPE.DAYTIME_DURATION, {
  name: 'dayTimeDuration',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const parsed = parseDayTimeDuration(lexical);
    if (!parsed) {
      throw fail('dayTimeDuration', lexical);
    }
    log.debug("Leaving parse().");
    return parsed;
  },
  write: function (value) {
    log.debug("Entering write().");
    const negative = value.seconds < 0;
    let seconds = Math.abs(value.seconds);
    const days = Math.floor(seconds / 86400);
    seconds -= days * 86400;
    const hours = Math.floor(seconds / 3600);
    seconds -= hours * 3600;
    const minutes = Math.floor(seconds / 60);
    seconds -= minutes * 60;
    log.debug("Leaving write().");
    return (negative ? '-' : '') + 'P' + days + 'DT' + hours + 'H' +
           minutes + 'M' + seconds + 'S';
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a.seconds === b.seconds;
  },
  compare: function (a, b) {
    log.debug("Entering compare().");
    log.debug("Leaving compare().");
    return a.seconds < b.seconds ? -1 : (a.seconds > b.seconds ? 1 : 0);
  }
});

define(TYPE.RFC822NAME, {
  name: 'rfc822Name',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const parsed = parseRfc822Name(lexical);
    if (!parsed) {
      throw fail('rfc822Name', lexical);
    }
    // A.3.9: string-from-rfc822Name gives the value "in the form it was originally
    // represented in XML form", and the typed regexp-match is defined
    // through it — so the text is kept beside the parsed parts, and equality
    // still compares the parts.
    parsed.original = trimmed(lexical);
    log.debug("Leaving parse().");
    return parsed;
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return typeof value.original === 'string' ? value.original
      : value.local + '@' + value.domain;
  },
  // See defect 3: the domain was folded at parse time, the local part was not.
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a.local === b.local && a.domain === b.domain;
  }
});

define(TYPE.X500NAME, {
  name: 'x500Name',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const parsed = parseX500Name(lexical);
    if (!parsed) {
      throw fail('x500Name', lexical);
    }
    // A.3.9: string-from-x500Name gives the value "in the form it was originally
    // represented in XML form", and the typed regexp-match is defined
    // through it — so the text is kept beside the parsed parts, and equality
    // still compares the parts.
    parsed.original = trimmed(lexical);
    log.debug("Leaving parse().");
    return parsed;
  },
  write: function (value) {
    log.debug("Entering write().");
    if (typeof value.original === 'string') {
      log.debug("Leaving write(). As written.");
      return value.original;
    }
    log.debug("Leaving write().");
    return value.rdns.map(function (rdn) {
      return rdn.attribute.toUpperCase() + '=' + rdn.value;
    }).join(',');
  },
  equal: x500Equal
});

define(TYPE.DNSNAME, {
  name: 'dnsName',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const parsed = parseDnsName(lexical);
    if (!parsed) {
      throw fail('dnsName', lexical);
    }
    // A.3.9: string-from-dnsName gives the value "in the form it was originally
    // represented in XML form", and the typed regexp-match is defined
    // through it — so the text is kept beside the parsed parts, and equality
    // still compares the parts.
    parsed.original = trimmed(lexical);
    log.debug("Leaving parse().");
    return parsed;
  },
  write: function (value) {
    log.debug("Entering write().");
    if (typeof value.original === 'string') {
      log.debug("Leaving write(). As written.");
      return value.original;
    }
    if (value.ports.low === null && value.ports.high === null) {
      log.debug("Leaving write().");
      return value.host;
    }
    log.debug("Leaving write().");
    return value.host + ':' + (value.ports.low === null ? ''
                                                        : value.ports.low) +
           (value.ports.low === value.ports.high ? ''
             : '-' + (value.ports.high === null ? '' : value.ports.high));
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a.host === b.host && portsEqual(a.ports, b.ports);
  }
});

define(TYPE.IPADDRESS, {
  name: 'ipAddress',
  parse: function (lexical) {
    log.debug("Entering parse().");
    const parsed = parseIpAddress(lexical);
    if (!parsed) {
      throw fail('ipAddress', lexical);
    }
    // A.3.9: string-from-ipAddress gives the value "in the form it was originally
    // represented in XML form", and the typed regexp-match is defined
    // through it — so the text is kept beside the parsed parts, and equality
    // still compares the parts.
    parsed.original = trimmed(lexical);
    log.debug("Leaving parse().");
    return parsed;
  },
  write: function (value) {
    log.debug("Entering write().");
    if (typeof value.original === 'string') {
      log.debug("Leaving write(). As written.");
      return value.original;
    }
    // Rebuilt from the parts: an IPv6 address and mask go back in their
    // brackets, and the port range is kept. Until 2026-11-13 both were
    // dropped, and what came out of an IPv6 value did not parse.
    const v6 = value.address.indexOf(':') >= 0;
    const wrap = function (part) {
      return v6 ? '[' + part + ']' : part;
    };
    const ports = value.ports;
    let portText = '';
    if (ports.low !== null || ports.high !== null) {
      portText = ':' + (ports.low === null ? '' : ports.low) +
        (ports.low === ports.high ? ''
          : '-' + (ports.high === null ? '' : ports.high));
    }
    log.debug("Leaving write().");
    return wrap(value.address) + (value.mask ? '/' + wrap(value.mask) : '') +
      portText;
  },
  equal: function (a, b) {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    return a.address === b.address && a.mask === b.mask &&
           portsEqual(a.ports, b.ports);
  }
});

define(TYPE.XPATH_EXPRESSION, {
  name: 'xpathExpression',
  // An xpathExpression carries the CATEGORY it selects within and the
  // namespace bindings in scope where it was written, neither of which is in
  // the lexical form — so the XML reader attaches them and this parser holds
  // only the expression itself. A value built from a bare string is therefore
  // incomplete on purpose rather than by omission; `xacml_xml.js` is the only
  // thing that constructs a usable one.
  parse: function (lexical) {
    log.debug("Entering parse().");
    log.debug("Leaving parse().");
    return { xpath: trimmed(lexical), category: null, namespaces: {} };
  },
  write: function (value) {
    log.debug("Entering write().");
    log.debug("Leaving write().");
    return value.xpath;
  },
  // Section A.3.15: two xpathExpressions are never compared for equality —
  // there is no `xpathExpression-equal` function in XACML at all. Present so
  // that the table has no hole, and it refuses rather than guessing.
  equal: function () {
    log.debug("Entering equal().");
    log.debug("Leaving equal().");
    throw model.processingError(
      'xpathExpression values cannot be compared for equality. XACML ' +
      'defines no such function; a policy that needs one is asking for ' +
      'xpath-node-count or one of the XPath-based match functions.');
  }
});

// ---------------------------------------------------------------------------
// LOOKUP, WITH THE TWO LEGACY DURATION SPELLINGS ALREADY HANDLED.
// ---------------------------------------------------------------------------
/**
 * Looks up a datatype's row, accepting the two legacy duration spellings.
 *
 * @param uri - the datatype URI
 * @returns the table row, or null for an unknown datatype
 */
function typeOf(uri) {
  log.debug('Entering typeOf(). uri=' + uri);
  // An own member only (2026-11-12): `constructor` is no datatype.
  const row = ownMembers.read(TYPES, model.canonicalType(uri));
  if (!row) {
    log.debug('Leaving typeOf(). Unknown.');
    return null;
  }
  log.debug('Leaving typeOf(). ' + row.name + '.');
  return row;
}

// ---------------------------------------------------------------------------
// PARSE A LEXICAL FORM AT A NAMED TYPE, RAISING THE RIGHT INDETERMINATE.
//
// The distinction this preserves is the one a Response carries: an UNKNOWN
// datatype is a syntax error in the policy, and a bad lexical form at a known
// type is also a syntax error but names the value. Collapsing them into one
// message makes a typo in a URI look like a typo in a date.
// ---------------------------------------------------------------------------
/**
 * Parses a lexical form at a named datatype.
 *
 * @param typeUri - the datatype URI
 * @param lexical - the lexical form
 * @returns the parsed value
 * @throws a syntax-error status when the datatype is unknown or the lexical
 * form is not valid for it
 */
function parseValue(typeUri, lexical) {
  log.debug('Entering parseValue(). type=' + typeUri);
  const row = typeOf(typeUri);
  if (!row) {
    log.debug('Leaving parseValue(). Unknown datatype.');
    throw model.syntaxError('Unknown datatype "' + typeUri + '".',
                            { type: typeUri });
  }
  const value = row.parse(lexical);
  log.debug('Leaving parseValue(). Parsed as ' + row.name + '.');
  return value;
}

/**
 * Writes a value back as its datatype's lexical form.
 *
 * @param typeUri - the datatype URI
 * @param value - a value parsed at that datatype
 * @returns the lexical form
 * @throws a syntax-error status when the datatype is unknown
 */
function writeValue(typeUri, value) {
  log.debug("Entering writeValue().");
  const row = typeOf(typeUri);
  if (!row) {
    throw model.syntaxError('Unknown datatype "' + typeUri + '".',
                            { type: typeUri });
  }
  log.debug("Leaving writeValue().");
  return row.write(value);
}

/**
 * Tests two values of one datatype for equality by that type's own rule.
 *
 * Not string equality: integers are BigInt, `NaN` equals `NaN` for doubles,
 * and several types compare canonically.
 * @param typeUri - the datatype URI
 * @param left - the first parsed value
 * @param right - the second parsed value
 * @returns true when the values are equal
 * @throws a syntax-error status when the datatype is unknown
 */
function equalValues(typeUri, left, right) {
  log.debug("Entering equalValues().");
  const row = typeOf(typeUri);
  if (!row) {
    throw model.syntaxError('Unknown datatype "' + typeUri + '".',
                            { type: typeUri });
  }
  log.debug("Leaving equalValues().");
  return row.equal(left, right);
}

/**
 * The seventeen XACML 3.0 datatypes: parsing, writing, equality and order.
 *
 * A row of `TYPES` is the whole of what a type is; `xacml_functions.js` is
 * generated over this table.
 * @namespace
 */
module.exports = {
  TYPES: TYPES,
  typeOf: typeOf,
  parseValue: parseValue,
  writeValue: writeValue,
  equalValues: equalValues,
  compareTemporal: compareTemporal,
  daysFromCivil: daysFromCivil,
  instantSeconds: instantSeconds,
  timezoneText: timezoneText
};
