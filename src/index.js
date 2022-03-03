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

// effectively adds a role to a user.
// returns true if added, false if already in the policy.
async function addRoleToPrincipal ({
  projectId,
  token,
  roleName,
  principal
}) {
  try {
    // build role ID string
    const role = `projects/${projectId}/roles/${roleName}`
    // get the current policy
    const policy = await getIamPolicy(projectId, token)
    // find the bindings for our role
    let binding = policy.bindings.find(v => v.role === role)
    // if binding didn't exist, add it to policy
    if (!binding) {
      binding = {
        role,
        members: []
      }
      policy.bindings.push(binding)
    }
    // find user in binding
    const isMember = binding.members.find(v => v === principal)
    if (!isMember) {
      // add principal
      binding.members.push(principal)
      // update google and return result, which is the modified policy
      return setIamPolicy(projectId, token, policy)
    } else {
      // do nothing - return unmodified policy
      return policy
    }
  } catch (e) {
    throw e
  }
}

// effectively adds a role to a user.
// returns true if added, false if already in the policy.
async function removeRoleFromPrincipal ({
  projectId,
  token,
  roleName,
  principal
}) {
  try {
    // build role ID string
    const role = `projects/${projectId}/roles/${roleName}`
    // get the current policy
    const policy = await getIamPolicy(projectId, token)
    // find the bindings for our role
    let binding = policy.bindings.find(v => v.role === role)
    // if binding didn't exist
    if (!binding) {
      // do nothing - return unmodified policy
      return policy
    }
    // find user in binding
    const index = binding.members.findIndex(v => v === principal)
    // if user not a member of binding, nothing to do
    if (index < 0) {
      // user does not have role - return unmodified policy
      return policy
    } else {
      // remove principal from the role members
      binding.members.splice(index, 1)
      // update google and return result, which is the modified policy
      return setIamPolicy(projectId, token, policy)
    }
  } catch (e) {
    throw e
  }
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
  setIamPolicy,
  addRoleToPrincipal,
  removeRoleFromPrincipal
}