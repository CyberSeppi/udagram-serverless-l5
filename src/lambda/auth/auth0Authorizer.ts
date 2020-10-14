import { CustomAuthorizerEvent, CustomAuthorizerHandler, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'
import * as AWS from 'aws-sdk'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const secretId = process.env.AUTH_0_SECRET_ID
const secretField = process.env.AUTH_0_SECRET_FIELD


const client = new AWS.SecretsManager()

//cached secret if a lambda instance is reused
let cachedSecret: string

export const handler: CustomAuthorizerHandler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {

    try {
        console.log('Processing event ', event)
        const decodedToken = await verifyToken(event.authorizationToken)

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

    async function verifyToken(authorizationToken: String): Promise<JwtToken> {

        if (!authorizationToken) {
            throw new Error('no authentication header')
        }

        console.log('Processing Token ', authorizationToken)

        if (!authorizationToken.toLocaleLowerCase().startsWith('bearer')) {
            throw new Error('invalid authentication header')
        }

        const split = authorizationToken.split(' ')

        const token = split[1]

        const secretObject: any = await getSecret()
        const secret = secretObject[secretField]


        return verify(token, secret) as JwtToken
    }
}

async function getSecret() {
    if (cachedSecret) return cachedSecret

    const data = await client.getSecretValue({
        SecretId: secretId
    }).promise()

    cachedSecret = data.SecretString

    return JSON.parse(cachedSecret)
}