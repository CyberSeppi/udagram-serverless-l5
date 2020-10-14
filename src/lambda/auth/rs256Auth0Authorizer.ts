import { CustomAuthorizerEvent, CustomAuthorizerHandler, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

//const secretId = process.env.AUTH_0_SECRET_ID
//const secretField = process.env.AUTH_0_SECRET_FIELD
const auth0_cert = process.env.AUTH0_CERT



export const handler:  CustomAuthorizerHandler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {

    console.log("AUTH0-CERT: ",process.env.AUTH0_CERT)

    try {
        console.log('Processing event ', event)
        const decodedToken = verifyToken(event.authorizationToken)

        console.log(`User ${decodedToken.sub} was authorized`)

        return {
            principalId: decodedToken.sub,
            policyDocument: {
                Version: '2012-10-17',
                Statement: [
                    {
                        Action: 'execute-api:Invoke',
                        Effect: 'Allow',
                        Resource: '*'
                    }
                ]
            }
        }
    } catch (e) {
        console.log('User was not authorized', e.message)

        return {
            principalId: 'user',
            policyDocument: {
                Version: '2012-10-17',
                Statement: [
                    {
                        Action: 'execute-api:Invoke',
                        Effect: 'Deny',
                        Resource: '*'
                    }
                ]
            }
        }

    }

    function verifyToken(authorizationToken: String): JwtToken {
     // function verifyToken(authorizationToken: String, secret:string): JwtToken {

        if (!authorizationToken) {
            throw new Error('no authentication header')
        }

        console.log('Processing Token ', authorizationToken)

        if (!authorizationToken.toLocaleLowerCase().startsWith('bearer')) {
            throw new Error('invalid authentication header')
        }

        const split = authorizationToken.split(' ')

        const token = split[1]


        return verify(token, auth0_cert.replace(/\\n/gm, '\n'), { algorithms: ['RS256'] }) as JwtToken
    }
}

