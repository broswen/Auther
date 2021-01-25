'use strict';
const middy = require('@middy/core');
const httpErrorHandler = require('@middy/http-error-handler');
const createError = require('http-errors');

const jwt = require('jsonwebtoken');
const cookie = require('cookie');

const privateHandler = async event => {

  console.log(event);
  const {token} = cookie.parse(event.headers.Cookie);

  const decodedJwt = jwt.decode(token);

  return {
    statusCode: 200,
    body: `hello, ${decodedJwt.sub}`
  };
};

const handler = middy(privateHandler)
  .use(httpErrorHandler());

module.exports = { handler };