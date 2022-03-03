const fs = require('fs')
const lib = require('../src')
require('dotenv').config()
// permission scopes to use
const scopes = 'https://www.googleapis.com/auth/cloud-platform'

async function main (projectId, roleName, principal) {
  try {
    const credsFile = fs.readFileSync('./secret/' + projectId + '.json', 'utf-8')
    const creds = JSON.parse(credsFile)
    // console.log(creds)
    const token = await lib.getAccessToken(creds, scopes)
    // console.log(token)

    // const roles = await lib.listServiceAccounts(projectId, token['access_token'])
    // const roles = await lib.listProjectRoles(projectId, token['access_token'])
    // const roles = await lib.listOrgRoles(process.env.ORG_ID, token['access_token'])
    // console.log(roles)

    // const principals = await lib.listProjectPrincipals(projectId, token['access_token'])
    // console.log(principals)

    const policy = await lib.getIamPolicy(projectId, token['access_token'])
    console.log('existing policy:', policy)
    const role = `projects/${projectId}/roles/${roleName}`
    // find the bindings for our role
    let binding = policy.bindings.find(v => v.role === role)
    // console.log(binding)
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
      // update google
      console.log('updated policy:', JSON.stringify(policy, null, 2))
      const result = await lib.setIamPolicy(projectId, token['access_token'], policy)
      console.log('added user', principal, 'to role', roleName, ':', result)
      return
    } else {
      // do nothing
      console.log(principal, 'is already a member of role binding', roleName)
      return
    }
  } catch (e) {
    console.log(e)
  }
}

main(process.env.PROJECT_ID, process.env.ROLE, process.env.USERNAME)