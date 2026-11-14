// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: xacml_request.js
//
// ---------------------------------------------------------------------------
// ONE AUTHORIZATION REQUEST, IN THE ENGINE'S SHAPE.
//
// The XACML page's decision form names a subject, an action, a resource
// and any number of extra attribute rows. `xacml_workbench.js`'s
// requestFromForm() hands them to this builder, which groups them by
// category, types each value and returns the request model
// `xacml_model.js` describes and `xacml_pdp.js` evaluates. A pasted XACML
// or JSON Profile request does not come through here: `xacml_xml.js` and
// `xacml_json.js` read those straight into the same model.
//
// IT DECIDES NOTHING. Which facts go in is the form's business; the builder
// only makes sure they are spelt, typed and grouped one way.
// ---------------------------------------------------------------------------

const { log } = require('../xacml_runtime');
const model = require('./xacml_model');

class AuthorizationRequest {
  // `options`:
  //   includeInResult  whether each attribute asks to be returned with the
  //                    result. Default true; the decision form says yes.
  //   dropEmpty        whether an empty or absent VALUE is left out of its
  //                    bag rather than sent as ''. Default false.
  //   returnPolicyIdList  default true.
  constructor(options) {
    log.debug("Entering AuthorizationRequest.constructor().");
    const given = options || {};
    this.includeInResult = given.includeInResult !== false;
    this.dropEmpty = !!given.dropEmpty;
    this.returnPolicyIdList = given.returnPolicyIdList !== false;
    // In the order a category was first named, so a request is built the
    // same every time and a reader of a logged one finds subject first.
    /** @type {Array<{category: string, attributes: any[]}>} */
    this.categories = [];
    log.debug("Leaving AuthorizationRequest.constructor().");
  }

  // The category's entry, made the first time it is named. Naming one with
  // no attributes sends an EMPTY category; the decision form always sends
  // the access-subject, action and environment categories, empty or not.
  category(id) {
    log.debug("Entering AuthorizationRequest.category().");
    let found = this.categories.filter(function (one) {
      return one.category === id;
    })[0];
    if (!found) {
      found = { category: id, attributes: [] };
      this.categories.push(found);
    }
    log.debug("Leaving AuthorizationRequest.category().");
    return found;
  }

  // ONE ATTRIBUTE, MULTI-VALUED: a bag rather than a value everywhere,
  // because every one of these genuinely is one. An empty list is sent as an
  // empty bag, which XACML reads as "nobody said" — the same as leaving the
  // attribute out.
  attribute(categoryId, attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.attribute().");
    const self = this;
    const list = (values || []).filter(function (one) {
      return !self.dropEmpty ||
             (one !== undefined && one !== null && String(one) !== '');
    });
    this.category(categoryId).attributes.push({
      attributeId: attributeId,
      issuer: null,
      includeInResult: this.includeInResult,
      values: list.map(function (one) {
        return { type: type || model.TYPE.STRING, lexical: String(one) };
      })
    });
    log.debug("Leaving AuthorizationRequest.attribute().");
    return this;
  }

  // ---------------------------------------------------------------------------
  // THE FOUR CATEGORIES, by name.
  // ---------------------------------------------------------------------------
  subject(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.subject().");
    log.debug("Leaving AuthorizationRequest.subject().");
    return this.attribute(model.CATEGORY.ACCESS_SUBJECT, attributeId, values,
                          type);
  }

  resource(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.resource().");
    log.debug("Leaving AuthorizationRequest.resource().");
    return this.attribute(model.CATEGORY.RESOURCE, attributeId, values, type);
  }

  action(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.action().");
    log.debug("Leaving AuthorizationRequest.action().");
    return this.attribute(model.CATEGORY.ACTION, attributeId, values, type);
  }

  environment(attributeId, values, type) {
    log.debug("Entering AuthorizationRequest.environment().");
    log.debug("Leaving AuthorizationRequest.environment().");
    return this.attribute(model.CATEGORY.ENVIRONMENT, attributeId, values,
                          type);
  }

  // ---------------------------------------------------------------------------
  // THE TWO XACML-DEFINED IDENTIFIERS THE FORM FILLS IN.
  // ---------------------------------------------------------------------------

  // The resource-id. A string unless the caller names a type; the
  // decision form sends its resource as an anyURI.
  target(id, type) {
    log.debug("Entering AuthorizationRequest.target().");
    log.debug("Leaving AuthorizationRequest.target().");
    return this.resource(model.ATTRIBUTE.RESOURCE_ID, [id], type);
  }

  // The action-id.
  requestedAction(id) {
    log.debug("Entering AuthorizationRequest.requestedAction().");
    log.debug("Leaving AuthorizationRequest.requestedAction().");
    return this.action(model.ATTRIBUTE.ACTION_ID, [id]);
  }

  // The request, in the engine's shape (`xacml_model.js`).
  build() {
    log.debug("Entering AuthorizationRequest.build().");
    const out = {
      returnPolicyIdList: this.returnPolicyIdList,
      combinedDecision: false,
      categories: this.categories.map(function (one) {
        return { category: one.category, id: null, content: null,
                 attributes: one.attributes.slice(0) };
      })
    };
    log.debug("Leaving AuthorizationRequest.build(). " +
              out.categories.length + " categories.");
    return out;
  }
}

module.exports = {
  AuthorizationRequest: AuthorizationRequest
};
