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
    const token = (await lib.getAccessToken(creds, scopes))['access_token']
    // console.log(token)

    // const roles = await lib.listServiceAccounts(projectId, token['access_token'])
    // const roles = await lib.listProjectRoles(projectId, token['access_token'])
    // const roles = await lib.listOrgRoles(process.env.ORG_ID, token['access_token'])
    // console.log(roles)

    // const principals = await lib.listProjectPrincipals(projectId, token['access_token'])
    // console.log(principals)

    // console.log('existing policy:', policy)
    
    const results = await lib.addRoleToPrincipal({
      projectId,
      token,
      roleName,
      principal
    })
    // const results = await lib.removeRoleFromPrincipal({
    //   projectId,
    //   token,
    //   roleName,
    //   principal
    // })
    console.log(results)
  } catch (e) {
    console.log(e)
  }
}

// go
main(process.env.PROJECT_ID, process.env.ROLE, process.env.USERNAME)