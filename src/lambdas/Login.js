'use strict';
const AWS = require('aws-sdk');
const DDB = new AWS.DynamoDB.DocumentClient();
const middy = require('@middy/core');
const jsonBodyParser = require('@middy/http-json-body-parser');
const httpErrorHandler = require('@middy/http-error-handler');
const validator = require('@middy/validator');
const createError = require('http-errors');

const jwt = require('jsonwebtoken');

const {hashSaltPassword} = require('./utils');

const inputSchema = {
  type: 'object',
  properties: {
    body: {
      type: 'object',
      properties: {
        email: { type: 'string', minLength: 1 },
        password: { type: 'string', minLength: 1 }
      },
      required: ['email', 'password']
    }
  }
}

const login = async event => {

  const {email, password, code} = event.body;

  const params = {
    TableName: process.env.USER_TABLE,
    Key: {
      PK: `A#${email}`
    }
  }

  let userDetails;
  try {
    userDetails = await DDB.get(params).promise();
  } catch (error) {
    console.error(error);
    throw createError(401, 'unauthorized');
  }

  if (userDetails.Item === undefined) throw createError(401, 'unauthorized');

  let saltedAndHashedPassword = hashSaltPassword(password);

  if (saltedAndHashedPassword !== userDetails.Item.password) throw createError(401, 'unauthorized')

  const token = jwt.sign({
    iss: 'Auther',
    sub: email
    }, process.env.SECRET, {expiresIn: 300});
  const refreshToken = jwt.sign({
    iss: 'Auther',
    sub: email
    }, process.env.SECRET, {expiresIn: 600});

  const params2 = {
    TableName: process.env.USER_TABLE,
    Key: {
      PK: `A#${email}`
    },
    UpdateExpression: 'set #rt = :rt',
    ExpressionAttributeNames: {
      '#rt': 'refreshtoken'
    },
    ExpressionAttributeValues: {
      ':rt': refreshToken
    }
  }

  try {
    await DDB.update(params2).promise();
  } catch (error) {
    console.error(error);
    throw createError(500, 'token error');
  }


  return {
    statusCode: 200,
    body: "OK",
    multiValueHeaders: {
      'Set-Cookie': [`token=${token}; HttpOnly`, `refreshtoken=${refreshToken}`]
    }
  };
};

const handler = middy(login)
  .use(jsonBodyParser())
  .use(validator({inputSchema}))
  .use(httpErrorHandler());

module.exports = { handler };