// File: xacml_xml_parser.js
//
// The XML parser the policy reader uses. A document type or an entity
// declaration is refused before the parser sees it. Malformed documents
// are reported through onError, which is the spelling @xmldom/xmldom
// 0.9 accepts.

'use strict';

var xmldom = require("@xmldom/xmldom");
var log = require("../xacml_runtime").log;

var DECLARATION = /<!\s*(DOCTYPE|ENTITY)\b/i;

/**
 * Names the declaration a document carries that this parser refuses.
 *
 * @param {*} source - the document text
 * @returns {string} DOCTYPE or ENTITY, or '' when it carries neither
 */
function declarationIn(source) {
  log.debug("Entering declarationIn().");
  var match = DECLARATION.exec(String(source == null ? "" : source));
  log.debug("Leaving declarationIn().");
  return match ? match[1].toUpperCase() : "";
}

/**
 * xmldom's DOMParser, refusing a document type or an entity declaration.
 *
 * @param {object} [options] - xmldom's options
 */
function DOMParser(options) {
  log.debug("Entering DOMParser().");
  this.inner = new xmldom.DOMParser(options);
  this.refusalHandler = options && typeof options.onError === "function"
    ? options.onError : null;
  log.debug("Leaving DOMParser().");
}

/**
 * Parses a document as XML, unless it declares a document type or an
 * entity. Whatever type the caller names, the inner parse is a literal
 * application/xml one, so this wrapper can never become an HTML parse
 * (tests/xml_parse_inert.js reads every parse call for that literal).
 *
 * @param {string} source - the document text
 * @returns {Document} the document
 */
function parseXml(source) {
  log.debug("Entering parseXml().");
  var found = declarationIn(source);
  if (found) {
    var message = "the document carries a <!" + found +
      "> declaration, which this parser refuses.";
    if (this.refusalHandler) {
      this.refusalHandler("fatalError", message);
    }
    log.debug("Leaving parseXml(). A declaration.");
    throw new Error(message);
  }
  log.debug("Leaving parseXml().");
  return this.inner.parseFromString(source, "application/xml");
}

DOMParser.prototype.parseFromString = parseXml;

module.exports = {
  DOMParser: DOMParser,
  XMLSerializer: xmldom.XMLSerializer,
  declarationIn: declarationIn
};
