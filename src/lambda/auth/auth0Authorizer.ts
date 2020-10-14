import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

import * as middy from 'middy'
import { secretsManager} from 'middy/middlewares'


const secretId = process.env.AUTH_0_SECRET_ID
const secretField = process.env.AUTH_0_SECRET_FIELD



export const handler = middy(async (event: CustomAuthorizerEvent, context): Promise<CustomAuthorizerResult> => {

    try {
        console.log('Processing event ', event)
        const decodedToken = verifyToken(event.authorizationToken, context.AUTH0_SECRET[secretField])

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

    function verifyToken(authorizationToken: String, secret:string): JwtToken {

        if (!authorizationToken) {
            throw new Error('no authentication header')
        }

        console.log('Processing Token ', authorizationToken)

        if (!authorizationToken.toLocaleLowerCase().startsWith('bearer')) {
            throw new Error('invalid authentication header')
        }

        const split = authorizationToken.split(' ')

        const token = split[1]


        return verify(token, secret) as JwtToken
    }
})

// async function getSecret() {
//     if (cachedSecret) return cachedSecret

//     const data = await client.getSecretValue({
//         SecretId: secretId
//     }).promise()

//     cachedSecret = data.SecretString

//     return JSON.parse(cachedSecret)
// }

handler.use(
    secretsManager({
        cache: true,
        cacheExpiryInMillis: 60000,
        throwOnFailedCall: true,
        secrets: {
            AUTH0_SECRET: secretId
        }
    })
)