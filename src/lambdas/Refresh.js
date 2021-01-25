'use strict';
const AWS = require('aws-sdk');
const DDB = new AWS.DynamoDB.DocumentClient();
const middy = require('@middy/core');
const jsonBodyParser = require('@middy/http-json-body-parser');
const httpErrorHandler = require('@middy/http-error-handler');
const createError = require('http-errors');

const cookie = require('cookie');
const jwt = require('jsonwebtoken');

const refresh = async event => {

  console.log(event);

  const {token, refreshtoken} = cookie.parse(event.headers.Cookie);

  //both tokens must exist
  if(token === undefined || refreshtoken === undefined) {
    throw createError(401, 'unauthorized');
  }

  //the original token must be valid, but can be expired
  try {
    jwt.verify(token, process.env.SECRET, {ignoreExpiration: true})
  } catch (error) {
    console.error("token signature is invalid");
    throw createError(401, 'invalid token');
  }

  //the refresh token must be valid and not expired
  try {
    jwt.verify(refreshtoken, process.env.SECRET, {ignoreExpiration: false})
  } catch (error) {
    console.error("refreshtoken signature is invalid or expired");
    throw createError(401, 'invalid refresh token');
  }
  
  const decodedJwt = jwt.decode(refreshtoken);
  console.log(decodedJwt);

  const params = {
    TableName: process.env.USER_TABLE,
    Key: {
      PK: `A#${decodedJwt.sub}`
    }
  }

  let userDetails;
  try {
    userDetails = await DDB.get(params).promise();
  } catch (error) {
    console.error(error);
    throw createError(500, 'error getting user');
  }

  console.log(userDetails);

  if (userDetails.Item === undefined) {
    throw createError(401, 'user not found');
  }

  if (userDetails.Item.refreshtoken !== refreshtoken) {
    //refresh token in DDB doesn't match
    throw createError(401, 'unauthorized');
  }

  const newToken = jwt.sign({
    iss: 'Auther',
    sub: userDetails.Item.email 
    }, process.env.SECRET, {expiresIn: 300});
  const newRefreshToken = jwt.sign({
    iss: 'Auther',
    sub: userDetails.Item.email
    }, process.env.SECRET, {expiresIn: 600});

  const params2 = {
    TableName: process.env.USER_TABLE,
    Key: {
      PK: `A#${userDetails.Item.email}`
    },
    UpdateExpression: 'set #rt = :rt',
    ExpressionAttributeNames: {
      '#rt': 'refreshtoken'
    },
    ExpressionAttributeValues: {
      ':rt': newRefreshToken
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
      'Set-Cookie': [`token=${newToken}; HttpOnly`, `refreshtoken=${newRefreshToken}`]
    }
  };
};

const handler = middy(refresh)
  .use(jsonBodyParser())
  .use(httpErrorHandler());

module.exports = { handler };