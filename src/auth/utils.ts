import { decode } from 'jsonwebtoken'

import { JwtToken } from './JwtToken'

/**
 * Parse a JWT token and return a user id
 * @param jwtToken JWT token to parse
 * @returns a user id from the JWT token
 */
export function getUserId(jwtToken: string): string {

  const decodedJWTToken = decode(jwtToken) as JwtToken

  console.log('getUserId - Decoded Token ', decodedJWTToken)


  return decodedJWTToken ? decodedJWTToken.sub : undefined
}
