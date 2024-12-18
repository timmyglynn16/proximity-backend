const express = require('express');
const { DynamoDBClient, QueryCommand, PutItemCommand } = require('@aws-sdk/client-dynamodb');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const { verifyAppleToken } = require('../services/appleAuthService'); // Apple Token Verification Service
require('dotenv').config();

// AWS Configuration
const dynamoDbClient = new DynamoDBClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const JWT_SECRET = process.env.JWT_SECRET || 'temporary-secret';

const router = express.Router();

// Sign-Up Endpoint
router.post(
  '/signup',
  [
    body('email').optional().isEmail().withMessage('Valid email is required'),
    body('password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('appleIdToken').optional().notEmpty().withMessage('Apple ID token is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, appleIdToken } = req.body;

    try {
      let verifiedEmail;
      let userName = null;

      // Apple Sign-Up Flow
      if (appleIdToken) {
        const { email: appleEmail } = await verifyAppleToken(appleIdToken);
        verifiedEmail = appleEmail;
      } 
      // Email/Password Sign-Up Flow
      else if (email && password) {
        verifiedEmail = email;

        // Check if the user already exists by email
        const queryParams = {
          TableName: 'profiles',
          KeyConditionExpression: 'email = :email',
          ExpressionAttributeValues: {
            ':email': { S: verifiedEmail },
          },
        };

        const existingUser = await dynamoDbClient.send(new QueryCommand(queryParams));
        if (existingUser.Items.length > 0) {
          return res.status(400).json({ message: 'User already exists' });
        }
      } else {
        return res.status(400).json({ message: 'Invalid sign-up request' });
      }

      // Generate userIdentifier and timestamp
      const userIdentifier = uuidv4();
      const timestamp = new Date().toISOString();

      // Hash password if provided (Email/Password sign-up)
      let hashedPassword = null;
      if (password) {
        hashedPassword = await bcrypt.hash(password, 10);
      }

      // Create new user object
      const putParams = {
        TableName: 'profiles',
        Item: {
          email: { S: verifiedEmail }, // Partition Key
          timestamp: { S: timestamp }, // Sort Key
          userIdentifier: { S: userIdentifier },
          createdAt: { S: timestamp },
          name: { S: userName || 'Unknown' },
          password: { S: hashedPassword || '' }, // Only for email/password sign-ups
        },
      };
      await dynamoDbClient.send(new PutItemCommand(putParams));

      // Generate JWT Token
      const token = jwt.sign({ userIdentifier }, JWT_SECRET, { expiresIn: '1h' });

      res.status(201).json({ token, user: putParams.Item });
    } catch (err) {
      console.error('Error creating user:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

module.exports = router;
