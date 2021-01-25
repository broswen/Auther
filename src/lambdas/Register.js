'use strict';
const AWS = require('aws-sdk');
const DDB = new AWS.DynamoDB.DocumentClient();
const middy = require('@middy/core');
const jsonBodyParser = require('@middy/http-json-body-parser');
const httpErrorHandler = require('@middy/http-error-handler');
const validator = require('@middy/validator');
const createError = require('http-errors');

const {hashSaltPassword} = require('./utils');

const inputSchema = {
  type: 'object',
  properties: {
    body: {
      type: 'object',
      properties: {
        email: { type: 'string', minLength: 1 },
        password: { type: 'string', minLength: 1 },
        code: { type: 'string', minLength: 1 }
      },
      required: ['email', 'password', 'code']
    }
  }
}

const register = async event => {

  const {email, password, code} = event.body;

  const params = {
    TableName: process.env.USER_TABLE,
    Key: {
      PK: `C#${code}`
    }
  }

  let codeDetails;
  try {
    codeDetails = await DDB.get(params).promise();
  } catch (error) {
    console.error(error);
    throw createError(500, 'error confirming registration code');
  }

  if (codeDetails.Item === undefined) throw createError(400, 'registration code not found');
  const now = new Date();
  const codeExpiry = new Date(codeDetails.Item.expires);
  if (now > codeExpiry) throw createError(400, 'expired registration code');

  let saltedAndHashedPassword = hashSaltPassword(password);

  const params2 = {
    TableName: process.env.USER_TABLE,
    Item: {
      PK: `A#${email}`,
      email,
      password: saltedAndHashedPassword,
      registered: now.toISOString(),
      code: `C#${code}`
    },
    ConditionExpression: 'attribute_not_exists(PK)'
  }

  try {
    await DDB.put(params2).promise();
  } catch (error) {
    console.error(error);
    throw createError(500, 'error registering details');
  }

  return {
    statusCode: 200,
    body: "OK"
  };
};


const handler = middy(register)
  .use(jsonBodyParser())
  .use(validator({inputSchema}))
  .use(httpErrorHandler());

module.exports = { handler };