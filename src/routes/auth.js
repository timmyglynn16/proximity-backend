const express = require('express');
const { DynamoDBClient, QueryCommand, PutItemCommand } = require('@aws-sdk/client-dynamodb');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const { verifyAppleToken } = require('../services/appleAuthService');
require('dotenv').config();

const router = express.Router();

// Dynamically configure AWS DynamoDB settings
const ENV = process.env.NODE_ENV || 'development';

if (
  !process.env.AWS_REGION ||
  !process.env.JWT_SECRET ||
  !process.env.AWS_ACCESS_KEY_ID ||
  !process.env.AWS_SECRET_ACCESS_KEY ||
  !process.env.DYNAMODB_TABLE_NAME
) {
  throw new Error(`Missing required environment variables for environment: ${ENV}`);
}

const dynamoDbClient = new DynamoDBClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const JWT_SECRET = process.env.JWT_SECRET;
const TABLE_NAME = process.env.DYNAMODB_TABLE_NAME;

// Sign-Up Endpoint
router.post(
  '/signup',
  [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('appleIdToken').optional().notEmpty().withMessage('Apple ID token is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, appleIdToken } = req.body;

    try {
      let verifiedEmail = email;
      let userName = null;

      // Handle Apple Sign-Up
      if (appleIdToken) {
        const { email: appleEmail } = await verifyAppleToken(appleIdToken);
        verifiedEmail = appleEmail;
      }

      // Check if user already exists
      const queryParams = {
        TableName: TABLE_NAME,
        KeyConditionExpression: 'email = :email',
        ExpressionAttributeValues: {
          ':email': { S: verifiedEmail },
        },
      };

      const existingUser = await dynamoDbClient.send(new QueryCommand(queryParams));
      if (existingUser.Items && existingUser.Items.length > 0) {
        return res.status(400).json({ message: 'User already exists' });
      }

      // Create user
      const userIdentifier = uuidv4();
      const timestamp = new Date().toISOString();
      const hashedPassword = await bcrypt.hash(password, 10);

      const putParams = {
        TableName: TABLE_NAME,
        Item: {
          email: { S: verifiedEmail },
          timestamp: { S: timestamp },
          userIdentifier: { S: userIdentifier },
          createdAt: { S: timestamp },
          name: { S: userName || 'Unknown' },
          password: { S: hashedPassword },
        },
      };
      await dynamoDbClient.send(new PutItemCommand(putParams));

      // Generate JWT
      const token = jwt.sign({ userIdentifier }, JWT_SECRET, { expiresIn: '1h' });

      res.status(201).json({ token, user: putParams.Item });
    } catch (err) {
      console.error('Error creating user:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Sign-In Endpoint
router.post(
  '/signin',
  [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      // Fetch user by email
      const queryParams = {
        TableName: TABLE_NAME,
        KeyConditionExpression: 'email = :email',
        ExpressionAttributeValues: {
          ':email': { S: email },
        },
      };

      const userData = await dynamoDbClient.send(new QueryCommand(queryParams));
      if (!userData.Items || userData.Items.length === 0) {
        return res.status(400).json({ message: 'Invalid email or password' });
      }

      const user = userData.Items[0];
      const hashedPassword = user.password.S;

      // Validate password
      const isPasswordValid = await bcrypt.compare(password, hashedPassword);
      if (!isPasswordValid) {
        return res.status(400).json({ message: 'Invalid email or password' });
      }

      // Generate JWT
      const token = jwt.sign({ userIdentifier: user.userIdentifier.S }, JWT_SECRET, { expiresIn: '1h' });

      res.status(200).json({
        token,
        user: {
          email: user.email.S,
          userIdentifier: user.userIdentifier.S,
          name: user.name.S || 'Unknown',
        },
      });
    } catch (err) {
      console.error('Error during sign-in:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

module.exports = router;
