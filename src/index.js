'use strict'
const fetch = require('./fetch')
const jwt = require('jsonwebtoken')

const authUrl = 'https://www.googleapis.com/oauth2/v4/token'
// Google uses SHA256 with RSA
const algorithm = 'RS256'

function createSignedJwt (creds, scope) {
  // ''' Create a Signed JWT from a service account JSON credentials file'''
  // get now time in seconds
  const issued = Math.floor(new Date().getTime() / 1000)
  // expire token in 30 minutes
  const expires = issued + 1800

  // Note: this token expires and cannot be refreshed. The token must be recreated
  // JWT Headers
  const options = {
    'algorithm': algorithm,
    'keyid': creds['private_key_id'],
    // 'expiresIn': '30m',
    // 'audience': authUrl,
    // 'issuer': creds['client_email'],
    // 'subject': creds['client_email']
  }

  // JWT Payload
  const payload = {
    'iss': creds['client_email'],
    'sub': creds['client_email'],
    'aud': authUrl,
    'iat': issued,
    'exp': expires,
    'scope': scope
  }

  // console.log('sign jwt', payload)

  return jwt.sign(payload, creds['private_key'], options)
}

function getAccessToken (creds, scope) {
  const signedJwt = createSignedJwt(creds, scope)
  // console.log(signedJwt)

  const body = {
    // ask for bearer token
    'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    'assertion': signedJwt
  }

  // send REST request
  return fetch(authUrl, {
    method: 'POST',
    body
  })
}

function listServiceAccounts (projectId, token) {
  // url = f'https://cloudresourcemanager.googleapis.com/v3/project/{projectId}:getIamPolicy'
  // project roles
  // const url = `https://iam.googleapis.com/v1/roles`
  // const url = `https://iam.googleapis.com/v1/organizations/${orgId}/roles`
  // const url = `https://iam.googleapis.com/v1/roles:queryGrantableRoles`
  const url = `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts`
  // all roles
  // url = 'https://iam.googleapis.com/v1/roles'
  

  const headers = {
    'Authorization': 'Bearer ' + token
  }

  return fetch(url, {headers})
}

function listProjectRoles (projectId, token) {
  const url = `https://iam.googleapis.com/v1/projects/${projectId}/roles`

  const headers = {
    'Authorization': 'Bearer ' + token
  }

  return fetch(url, {headers})
}

function listOrgRoles (orgId, token) {
  const url = `https://iam.googleapis.com/v1/organizations/${orgId}/roles`

  const headers = {
    'Authorization': 'Bearer ' + token
  }

  return fetch(url, {headers})
}

function listProjectPrincipals (projectId, token) {
  const url = `https://iam.googleapis.com/v1/projects/${projectId}/principals`

  const headers = {
    'Authorization': 'Bearer ' + token
  }

  return fetch(url, {headers})
}

function getIamPolicy (projectId, token) {
  const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:getIamPolicy`

  const headers = {
    'Authorization': 'Bearer ' + token
  }

  // const body = {
  //   options: {
  //     requestedPolicyVersion: 3
  //   }
  // }

  return fetch(url, {
    method: 'POST',
    headers,
    // body
  })
}

function setIamPolicy (projectId, token, policy) {
  const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:setIamPolicy`

  const headers = {
    'Authorization': 'Bearer ' + token
  }

  const body = {policy}

  return fetch(url, {
    method: 'POST',
    headers,
    body
  })
}

// get list of google APIs from discovery API
// url = 'https://www.googleapis.com/discovery/v1/apis'

module.exports = {
  listServiceAccounts,
  listProjectRoles,
  listOrgRoles,
  createSignedJwt,
  getAccessToken,
  listProjectPrincipals,
  getIamPolicy,
  setIamPolicy
}