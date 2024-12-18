const appleSignin = require('apple-signin-auth');

/**
 * Verifies the Apple ID token and returns the payload.
 * @param {string} token - The Apple ID token provided by the client.
 * @returns {Object} - The decoded token payload containing user details.
 */
async function verifyAppleToken(token) {
  try {
    const payload = await appleSignin.verifyIdToken(token, {
      audience: 'com.yourcompany.yourapp', // Replace with your app’s bundle ID
      ignoreExpiration: false, // Ensure token is not expired
    });

    // Extract necessary information from the payload
    const { email, sub: appleUserId } = payload;

    return { email, appleUserId }; // Return email and Apple user ID
  } catch (err) {
    console.error('Apple token verification failed:', err);
    throw new Error('Invalid Apple ID token');
  }
}

module.exports = { verifyAppleToken };
