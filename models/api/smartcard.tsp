// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: models/api/smartcard.tsp
//
// SMART CARDS AND OTP: two families in one file, because the page that calls
// them is one (smartcard.html) and so is docs/v0.9.5/smartcard.md.
//
// * Otp — POST /otp/verify sends a Yubico OTP validation request the PAGE
//   built and signed (the API key stays in the browser) to a YubiCloud-style
//   verifier, as the HTTP GET Validation Protocol 2.0 specifies.
// * Smartcard — the optional PC/SC reader relay, its sessions, and OTP-slot
//   challenge-response over HID. The reader is the machine this api runs
//   on; there is no host, port or caller-chosen path anywhere in a request.
//
// THE OUTCOMES, which every answer below keeps apart:
//
// * 400 — this service refused: a form that is not one, a verifier that is
//   not https, a reader name that is a URL, an APDU that is not hex.
// * 403 — the reader relay is off (smartcardReaderEnabled is not true).
//   Every smart-card route but the session close answers it before looking
//   at the body's VALUES; the schema's type checks come first.
// * 502 — the far end could not be reached: no verifier, no PC/SC library,
//   no reader, no HID device, no such session.
// * 200 — the far end ANSWERED. A verifier's status=BAD_OTP or an HTTP 4xx
//   is a 200, and so is a card's 6A82: that answer is what the page shows.
//
// WHERE THE CHECKS ARE. The schema holds the JSON types, and the session id,
// which the two session routes themselves used to check. Everything about a
// value is api/otp_verify.js's, api/smartcard_reader.js's or api/otp_hid.js's
// — the decision halves tests/smartcard_engine.js drives with no network and
// no reader — and each such member says so with @checkedInCode.

import "@typespec/http";
import "@typespec/openapi";
import "../lib/debugger_lib.tsp";
import "./common.tsp";

using Http;
using OpenAPI;
using IdProtoDebugger.Lib;

namespace IdProtoDebugger.Api.Otp {

  // ---------------------------------------------------------------------------
  // Requests.
  // ---------------------------------------------------------------------------

  /** A validation request the page already signed, and where to send it. */
  model VerifyRequest {
    /**
     * The signed fields, form-encoded: id, otp, nonce and h, and optionally
     * sl, timeout and timestamp. Sent as the GET's query string, unchanged.
     */
    @checkedInCode("api/otp_verify.js: present, no line break, at most 2048 bytes, a form of only the seven Validation Protocol 2.0 fields, with a digit client id, a 32-48 character modhex OTP, a 16-40 character nonce and a base64 h")
    @passthrough
    body?: string;

    /** A verifier URL of the caller's own. Wins over `server`. */
    @checkedInCode("api/otp_verify.js: an https URL with no userinfo, query string or '..'; the address policy installed on axios decides where it may go")
    verifier?: string | null;

    /** Which YubiCloud server, 1 to 5, when no verifier is named. */
    @checkedInCode("api/otp_verify.js: an integer 1 to 5, as a number or as text; absent or empty is 1")
    server?: float64 | string | null;

    /** Only false (or "false") turns off certificate verification. */
    sslValidate?: boolean | string | null;

    /** true (or "true") attaches the outbound exchange as http_exchange. */
    http_trace?: boolean | string | null;
  }

  // ---------------------------------------------------------------------------
  // Answers.
  // ---------------------------------------------------------------------------


  /**
   * What the verifier said. `ok` is the HTTP status being 2xx and nothing
   * more: the protocol's own status=OK or BAD_OTP is inside `body`, which the
   * page reads and checks against its nonce and the API key.
   */
  model VerifyAnswer {
    ok: boolean;
    status: int32;
    body: string;
    http_exchange?: HttpExchange;
  }

  /** The verifier could not be reached. `code` is the network's, or empty. */
  model Unreachable {
    error: string;
    code: string;
    http_exchange?: HttpExchange;
  }

  /** What /otp/verify will send, and to which servers. */
  model Limits {
    maxBodyBytes: int32;
    method: "GET";
    defaultVerifier: string;
    servers: {
      server: int32;
      host: string;
    }[];
    note: string;
  }

  // ---------------------------------------------------------------------------
  // Operations.
  // ---------------------------------------------------------------------------

  /**
   * Send a signed Yubico OTP validation request, as Validation Protocol 2.0's
   * HTTP GET. A verifier's answer, whatever it says, is a 200.
   */
  @tag("OTP")
  @route("/otp/verify")
  @post
  @operationId("otpVerify")
  op verify(@body body: VerifyRequest): Ok<VerifyAnswer> |
    BadRequest<IdProtoDebugger.Api.Refusal | IdProtoDebugger.Api.ModelRefusal> |
    BadGateway<Unreachable>;

  /** The size cap, the method and the five YubiCloud servers. */
  @tag("OTP")
  @route("/otp/limits")
  @get
  @operationId("otpLimits")
  op limits(): Ok<Limits>;
}

namespace IdProtoDebugger.Api.Smartcard {

  /** 403: the reader relay is off on this api. */
  @error
  model Forbidden<T> {
    @statusCode statusCode: 403;
    @body body: T;
  }

  // ---------------------------------------------------------------------------
  // Requests.
  // ---------------------------------------------------------------------------

  /** A sequence of APDUs, as /smartcard/transmit and a session take it. */
  model Apdus {
    /** One APDU in hex, when `apdus` is not an array. */
    @checkedInCode("api/smartcard_reader.js: an even number of hex characters, 4 to 8192 bytes")
    @passthrough
    apdu?: string | null;

    /** 1 to 16 APDUs in hex, sent in order on one connection. */
    @checkedInCode("api/smartcard_reader.js: 1 to 16, each an even number of hex characters, 4 to 8192 bytes")
    @passthrough
    apdus?: (string | null)[] | null;

    /**
     * Only false (or "false") turns off GET RESPONSE after 61xx and the
     * resend after 6Cxx, to show the raw exchange.
     */
    getResponse?: boolean | string | null;

    /** c0 (GET RESPONSE) or a5 (YKOATH SEND REMAINING). Absent is c0. */
    @checkedInCode("api/smartcard_reader.js: c0 or a5, any case")
    remainingIns?: string | null;
  }

  /** A PC/SC reader, by the name GET /smartcard/readers lists. */
  model ReaderName {
    @checkedInCode("api/smartcard_reader.js: not empty, at most 256 characters, no control character, and not a URL, a URI, a host and port or a filesystem path")
    reader?: string;
  }

  /** POST /smartcard/transmit. */
  model TransmitRequest {
    ...ReaderName;
    ...Apdus;
  }

  /** The session id POST /smartcard/session answered with. */
  model SessionId {
    @refusal(#{ message: "The session id is 32 hex characters." })
    @pattern("^[0-9a-f]{32}$")
    id: string;
  }

  /** POST /smartcard/session/transmit: the reader is the session's. */
  model SessionTransmitRequest {
    ...SessionId;
    ...Apdus;
  }

  /** POST /smartcard/otp/challenge. */
  model ChallengeRequest {
    /** The OTP slot's HID slot byte, in hex: 20, 28, 30 or 38. */
    @checkedInCode("api/otp_hid.js: 20, 28, 30 or 38, read as hex")
    slot?: string | null;

    /** Up to 64 bytes of hex. */
    @checkedInCode("api/otp_hid.js: an even number of hex characters, at most 64 bytes")
    @passthrough
    challenge?: string | null;

    /** Only false (or "false") selects the fixed 64-byte HMAC mode. */
    variable?: boolean | string | null;
  }

  // ---------------------------------------------------------------------------
  // Answers.
  // ---------------------------------------------------------------------------

  /** One APDU on the wire and the card's answer to it. */
  model Step {
    apdu: string;
    data: string;
    status: string;
  }

  /**
   * One APDU of the sequence, completed: its data across every GET RESPONSE,
   * the final status word, and each exchange that took.
   */
  model Exchange {
    data: string;
    status: string;
    steps: Step[];
  }

  /**
   * The card's answer. The top-level members are the LAST APDU's; `results`
   * has every one that ran, and the sequence stops at the first whose status
   * is not 90xx or 61xx.
   */
  model TransmitAnswer {
    ...Exchange;
    results: Exchange[];
  }

  /** An open session, and how long it may sit idle before it is closed. */
  model Session {
    id: string;
    idleMs: int64;
  }

  /** Whether the close found a session to close (with a card reset). */
  model Closed {
    closed: boolean;
  }

  /** The readers PC/SC lists. */
  model Readers {
    readers: string[];
  }

  /** An OTP slot's HMAC-SHA1 response, and the key that gave it. */
  model ChallengeAnswer {
    response: string;
    raw: string;
    device: string;
  }

  /** What the relay will and will not do, and why not where it cannot. */
  model Limits {
    enabled: boolean;

    /** The relay is on and a PC/SC library loads. */
    available: boolean;

    reason: string | null;
    maxApduBytes: int32;
    maxSequence: int32;
    reader: string;

    /** OTP challenge-response over HID. Reported unavailable when off. */
    hid: {
      available: boolean;
      reason: string | null;
    };
  }

  alias Refused = BadRequest<IdProtoDebugger.Api.Refusal |
    IdProtoDebugger.Api.ModelRefusal>;
  alias Off = Forbidden<IdProtoDebugger.Api.Refusal>;
  alias Unreachable = BadGateway<IdProtoDebugger.Api.Refusal>;

  // ---------------------------------------------------------------------------
  // Operations.
  // ---------------------------------------------------------------------------

  /** Whether the relay is on, and whether PC/SC and HID are there. */
  @tag("Smart card")
  @route("/smartcard/limits")
  @get
  @operationId("smartcardLimits")
  op limits(): Ok<Limits>;

  /** The readers on the machine this api runs on. */
  @tag("Smart card")
  @route("/smartcard/readers")
  @get
  @operationId("smartcardReaders")
  op readers(): Ok<Readers> | Off | Unreachable;

  /**
   * A sequence of APDUs on one connection, exclusive when there is more than
   * one. A card's status word, whatever it is, is a 200.
   */
  @tag("Smart card")
  @route("/smartcard/transmit")
  @post
  @operationId("smartcardTransmit")
  op transmit(@body body: TransmitRequest): Ok<TransmitAnswer> | Refused |
    Off | Unreachable;

  /** Open one exclusive connection for several requests. */
  @tag("Smart card")
  @route("/smartcard/session")
  @post
  @operationId("smartcardSessionOpen")
  op sessionOpen(@body body: ReaderName): Ok<Session> | Refused | Off |
    Unreachable;

  /** A sequence of APDUs in an open session. */
  @tag("Smart card")
  @route("/smartcard/session/transmit")
  @post
  @operationId("smartcardSessionTransmit")
  op sessionTransmit(@body body: SessionTransmitRequest): Ok<TransmitAnswer> |
    Refused | Off | Unreachable;

  /**
   * Close a session with a card reset. Not behind the relay switch: closing
   * one is always allowed, and an id that names none is `closed: false`.
   */
  @tag("Smart card")
  @route("/smartcard/session/close")
  @post
  @operationId("smartcardSessionClose")
  op sessionClose(@body body: SessionId): Ok<Closed> | Refused;

  /** OTP-slot challenge-response over HID, for a browser with no WebHID. */
  @tag("Smart card")
  @route("/smartcard/otp/challenge")
  @post
  @operationId("smartcardOtpChallenge")
  op otpChallenge(@body body: ChallengeRequest): Ok<ChallengeAnswer> |
    Refused | Off | Unreachable;
}
