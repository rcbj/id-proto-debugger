// File: media_type.js
//
// ---------------------------------------------------------------------------
// The media type comparison the JOSE "typ" header parameter needs, as one
// module rather than a spelling each page decides for itself.
//
// RFC 9068 section 2.1 tells an access-token issuer to set "typ" to
// "at+jwt", RECOMMENDING the "application/" prefix be omitted; its section 4
// tells a resource server to accept "at+jwt" or "application/at+jwt" and
// reject tokens carrying any other value. The prefix rule comes from RFC 7515
// section 4.1.9, which section 2.1 cites — and which also makes media type
// names case-insensitive, so "at+JWT", the spelling in RFC 9068's own
// Figure 2, is the same media type as section 7.1.1's registered "at+jwt".
// A check that compares strings for equality therefore fails tokens the RFC
// itself produces. That is not hypothetical: this debugger's own Validate
// Claims check accepted only "at+JWT" (Figure 2's spelling), and its RFC 9068
// Compliance check accepted only "at+jwt" and "application/at+jwt" — each
// page a different subset of the spellings the RFC uses.
//
// It is a module for the same reason jws.js and hash_tools.js are: it has NO
// DOM, so tests/media_type_engine.js drives it in node against spellings
// taken from the RFCs themselves — Figure 2's "at+JWT", section 4's
// "application/at+jwt", section 7.1.1's registered "at+jwt" — rather than
// against a round trip through a page, which agrees with itself whatever
// the comparison does.
// ---------------------------------------------------------------------------

// One leading "application/" prefix is dropped (RFC 7515 §4.1.9: the prefix
// may be omitted when no "/" appears in the value), and media type names are
// case-insensitive (§4.1.9 again), so the value is lowercased first. Only ONE
// prefix is dropped: "application/application/at+jwt" is not a spelling of
// anything.
function normalizeMediaType(value) {
  var lowered = value.toLowerCase();
  if (lowered.indexOf('application/') === 0) {
    lowered = lowered.slice('application/'.length);
  }
  return lowered;
}

// Do these two strings name the same media type? A non-string names none:
// JOSE header parameters are JSON strings, so a number or an object in a
// "typ" must fail the comparison rather than throw it.
function matchesMediaType(value, mediaType) {
  if (typeof value !== 'string' || typeof mediaType !== 'string') {
    return false;
  }
  return normalizeMediaType(value) === normalizeMediaType(mediaType);
}

module.exports = {
  matchesMediaType: matchesMediaType,
  normalizeMediaType: normalizeMediaType
};
