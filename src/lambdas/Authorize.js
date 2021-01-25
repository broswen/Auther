'use strict';

const cookie = require('cookie');
const jwt = require('jsonwebtoken');

const handler = async event => {

  const {token} = cookie.parse(event.headers.Cookie);
  console.log(token)
  console.log(event);

  let decodedJwt;
  let effect;
  try {
    jwt.verify(token, process.env.SECRET, {ignoreExpiration: false});
    decodedJwt = jwt.decode(token);
    console.log(decodedJwt);
    effect = 'allow';
  } catch (error) {
    console.error(error); 
    //jwt is invalid or expired
    //unauthorized
    effect = 'deny';
  }

  const policy = createPolicy(jwt.sub, effect, event.methodArn);

  console.log(JSON.stringify(policy));

  return policy
};

const createPolicy = (principalId, effect, methodArn) => {

  const base = methodArn.split("/")[0]
  const stage = methodArn.split("/")[1]
  const arn = base + "/" + stage + "/*/*"

  return {
    "principalId": principalId,
    "policyDocument": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "execute-api:Invoke",
          "Effect": effect,
          "Resource": arn
        }
      ]
    }
  }
}

module.exports = { handler };