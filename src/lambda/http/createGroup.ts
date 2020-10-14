//import { APIGatewayProxyHandler, APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda'
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda'
import 'source-map-support/register'
import * as AWS from 'aws-sdk'
import * as uuid from 'uuid'
import { getUserId } from '../../auth/utils'

import * as middy from 'middy'
import { cors } from 'middy/middlewares'

const docClient = new AWS.DynamoDB.DocumentClient()
const groupsTable = process.env.GROUPS_TABLE

//export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
export const handler = middy(async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  console.log('Processing event: ', event)
  const itemId = uuid.v4()

  const parsedBody = JSON.parse(event.body)
  console.log('Processing body ', parsedBody)

  const authorizationHeader = event.headers.Authorization
  const authToken = authorizationHeader.split(' ')[1]
  console.log('Auth-Token: ', authorizationHeader)
  const userId = authorizationHeader ? getUserId(authToken) : ""

  console.log('User Id is ', userId)

  const newItem = {
    id: itemId,
    userId: userId,
    ...parsedBody
  }

  await docClient.put({
    TableName: groupsTable,
    Item: newItem
  }).promise()

  return {
    statusCode: 201,
    body: JSON.stringify({
      newItem
    })
  }
})


handler.use(
  cors({
    credentials: true
  })
)