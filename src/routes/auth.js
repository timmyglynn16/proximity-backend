const express = require('express');
const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const router = express.Router();

AWS.config.update({ region: 'us-east-1' });
const dynamoDb = new AWS.DynamoDB.DocumentClient();

const JWT_SECRET = process.env.JWT_SECRET;

router.post('/signup', async (req, res) => {
  const { appleId, email, name } = req.body;

  const params = { TableName: 'Users', Key: { email } };
  const existingUser = await dynamoDb.get(params).promise();

  if (existingUser.Item) return res.status(400).json({ message: 'User already exists' });

  const newUser = { email, appleId, name, createdAt: new Date().toISOString() };
  await dynamoDb.put({ TableName: 'Users', Item: newUser }).promise();

  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, user: newUser });
});

module.exports = router;
