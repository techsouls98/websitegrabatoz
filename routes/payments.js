// routes/payments.js
const express = require('express');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const router = express.Router();
require('dotenv').config();

// Initiate N-Genius Payment
router.post('/api/payments/ngenius', async (req, res) => {
  const { order_id, amount } = req.body;

  if (!amount) return res.status(400).json({ error: 'Missing amount' });

  const generatedOrderId = order_id || uuidv4();

  try {
    // Step 1: Access token
    const tokenRes = await axios.post(
      `${process.env.NGENIUS_API_URL}/identity/auth/access-token`,
      null,
      {
        headers: {
          Authorization: `Basic ${process.env.NETWORK_API_SECRET}`,
          'Content-Type': 'application/vnd.ni-identity.v1+json',
        },
      }
    );

    const accessToken = tokenRes.data.access_token;

    // Step 2: Create order
    const reference = `ORDER-${generatedOrderId}-${Date.now()}`;
    const paymentRes = await axios.post(
      `${process.env.NGENIUS_API_URL}/transactions/outlets/${process.env.NG_OUTLET_ID}/orders`,
      {
        action: 'SALE',
        amount: {
          currencyCode: 'AED',
          value: Math.round(amount * 100), // ensure it's an integer
        },
        merchantAttributes: {
          redirectUrl: `${process.env.SITE_URI}/payment-callback.html?orderId=${generatedOrderId}`,
          cancelUrl: `${process.env.SITE_URI}/payment-canceled.html`
        },
        merchantOrderReference: reference,
      },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/vnd.ni-payment.v2+json',
        },
      }
    );

    const paymentUrl = paymentRes.data._links.payment.href;
    res.json({ success: true, paymentUrl });
  } catch (err) {
    console.error('N-Genius Payment Error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to initiate N-Genius payment', details: err.response?.data || err.message });
  }
});

// Payment Verification (Optional)
router.post('/api/payments/verify', async (req, res) => {
  const { paymentRef } = req.body;
  if (!paymentRef) return res.status(400).json({ error: 'Missing paymentRef' });

  try {
    const tokenRes = await axios.post(
      `${process.env.NGENIUS_API_URL}/identity/auth/access-token`,
      null,
      {
        headers: {
          Authorization: `Basic ${process.env.NETWORK_API_SECRET}`,
          'Content-Type': 'application/vnd.ni-identity.v1+json',
        },
      }
    );

    const accessToken = tokenRes.data.access_token;

    const verifyRes = await axios.get(
      `${process.env.NGENIUS_API_URL}/transactions/${paymentRef}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Accept': 'application/vnd.ni-payment.v2+json'
        },
      }
    );

    const status = verifyRes.data.state;
    res.json({ success: status === 'CAPTURED', status });
  } catch (err) {
    console.error('N-Genius Verify Error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to verify payment' });
  }
});

module.exports = router;