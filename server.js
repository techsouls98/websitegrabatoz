require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const db = require('./database'); 
const authenticate = require('./middleware/authMiddleware'); 
const path = require('path');
const nodemailer = require('nodemailer');
const app = express();
const paymentRoutes = require('./routes/payments');


// Middleware
app.use(cors()); 
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); 
app.use(paymentRoutes);
// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

app.get('/api/db-name', (req, res) => {
    const dbName = process.env.DB_NAME;
    res.json({ success: true, dbName });
});
// Register Endpoint (with email verification)
app.post('/register', async (req, res) => {
    const {
        name,
        email,
        password,
        confirmPassword,
        phone = '',
        address = '',
        country = '',
        state = '',
        city = '',
        zip_code = '',
    } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    try {
        const [existingUser] = await db.query('SELECT * FROM customers WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate verification token
        const verificationToken = jwt.sign({ email, name, hashedPassword, phone, address, country, state, city, zip_code }, process.env.JWT_SECRET, { expiresIn: '1h' });

        const verificationUrl = `${process.env.SITE_URI}:${process.env.PORT}/verify-email/${verificationToken}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify Your Email',
            html: `<p>Hi ${name},</p><p>Please verify your email by clicking <a href="${verificationUrl}">here</a>.</p>`,
        };

        // Send email
        await transporter.sendMail(mailOptions);

        res.status(201).json({ message: 'Verification email sent. Please check your inbox.' });

    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Email Verification Endpoint with redirect to login page
app.get('/verify-email/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const { email, name, hashedPassword, phone, address, country, state, city, zip_code } = decoded;

        const [existingUser] = await db.query('SELECT * FROM customers WHERE email = ?', [email]);
        if (existingUser.length > 0) {
            return res.redirect(`${process.env.SITE_URI}/Main-file-Marketpro/login.html`); // redirect if already verified
        }

        await db.query(
            `INSERT INTO customers (name, email, phone, status, password, address, country, state, city, zip_code)
            VALUES (?, ?, ?, 'Active', ?, ?, ?, ?, ?, ?)`,
            [name, email, phone, hashedPassword, address, country, state, city, zip_code]
        );

        // Redirecting user to login page after successful verification
        res.redirect(`${process.env.SITE_URI}:5501/Main-file-Marketpro/login.html`); // Change this to your actual login URL

    } catch (error) {
        console.error('Verification error:', error);
        res.status(400).send('Verification link is invalid or expired.');
    }
});


// Login API
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        // Check if the user exists
        const [rows] = await db.query('SELECT * FROM customers WHERE email = ?', [email]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const user = rows[0];

        // Compare passwords
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ accessToken: null, message: 'Invalid password.' });
        }

        // Generate a JWT token
        const token = jwt.sign(
            { id: user.id },
            process.env.JWT_SECRET || '04d063ae4d2932d2f0eb6fe569328eebdea5be494db648b1fb28048267c858ef',
            { expiresIn: 86400 } // 24 hours
        );

        res.status(200).json({
            id: user.id,
            name: user.name,
            email: user.email,
            accessToken: token,
        });
    } catch (err) {
        console.error('Error during login:', err.message);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Protected Endpoint Example
app.get('/protected', authenticate, async (req, res) => {
    try {
        res.status(200).json({ message: `Welcome, user ${req.user.id}` });
    } catch (err) {
        console.error('Error in protected endpoint:', err.message);
        res.status(500).json({ error: 'Server error during protected request' });
    }
});

const { Country, State, City } = require('country-state-city');

// New API endpoints for dynamic data
app.get('/api/countries', (req, res) => {
    try {
        const countries = Country.getAllCountries().map(country => ({
            name: country.name,
            isoCode: country.isoCode
        }));
        res.json(countries);
    } catch (error) {
        console.error('Error fetching countries:', error);
        res.status(500).json({ error: 'Failed to fetch countries' });
    }
});

app.get('/api/states', (req, res) => {
    try {
        const countryCode = req.query.country;
        if (!countryCode) {
            return res.status(400).json({ error: 'Country code is required' });
        }

        const states = State.getStatesOfCountry(countryCode).map(state => ({
            name: state.name,
            isoCode: state.isoCode
        }));
        res.json(states);
    } catch (error) {
        console.error('Error fetching states:', error);
        res.status(500).json({ error: 'Failed to fetch states' });
    }
});

app.get('/api/cities', (req, res) => {
    try {
        const countryCode = req.query.country;
        const stateCode = req.query.state;

        if (!countryCode || !stateCode) {
            return res.status(400).json({ error: 'Country and state codes are required' });
        }

        const cities = City.getCitiesOfState(countryCode, stateCode).map(city => ({
            name: city.name
        }));
        res.json(cities);
    } catch (error) {
        console.error('Error fetching cities:', error);
        res.status(500).json({ error: 'Failed to fetch cities' });
    }
});

// Existing guest creation endpoint (updated to handle new fields)
app.post('/api/guests', async (req, res) => {
    const connection = await db.getConnection();
    try {
        const { name, email, mobile, address, country, region, city, zip } = req.body;

        // Validation (same as before)
        const requiredFields = ['name', 'email', 'mobile', 'address', 'country', 'region', 'city', 'zip'];
        for (const field of requiredFields) {
            if (!req.body[field]) {
                return res.status(400).json({ error: `All fields are required (missing ${field})` });
            }
        }

        if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const guestId = uuidv4();
        const createdAt = new Date().toISOString().slice(0, 19).replace('T', ' ');

        await connection.query(
            `INSERT INTO guest (guest_id, name, email, mobile, address, country, region, city, zip, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [guestId, name, email, mobile, address, country, region, city, zip, createdAt]
        );

        res.json({
            success: true,
            guestId,
            name,
            message: 'Guest information stored successfully'
        });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Failed to process guest information' });
    } finally {
        connection.release();
    }
});

app.post('/api/orders', async (req, res) => {
    const { guest_id, customer_name, items, payment_type, shipping_address, shipping_info, card_info } = req.body;

    try {
        // Enhanced validation
        if (!guest_id) {
            return res.status(400).json({
                success: false,
                error: "Guest ID is required"
            });
        }

        if (!customer_name) {
            return res.status(400).json({
                success: false,
                error: "Customer name is required"
            });
        }

        if (!items || !Array.isArray(items)) {
            return res.status(400).json({
                success: false,
                error: "Invalid items data"
            });
        }

        if (!payment_type || !['cash', 'card'].includes(payment_type)) {
            return res.status(400).json({
                success: false,
                error: "Invalid payment type"
            });
        }

        if (!shipping_address || typeof shipping_address !== 'object' || !shipping_address.address) {
            return res.status(400).json({
                success: false,
                error: "Invalid shipping address"
            });
        }

        if (!shipping_info || typeof shipping_info !== 'object' || !shipping_info.contact) {
            return res.status(400).json({
                success: false,
                error: "Invalid shipping information"
            });
        }

        // Calculate total
        const total = items.reduce((acc, item) => acc + (item.price * item.quantity), 0);

        // Start transaction
        // await db.beginTransaction();

        try {
            // Insert order
            const [orderResult] = await db.query(
                `INSERT INTO onlineorders 
                (guest_id, customer_name, total_amount, payment_type, shipping_address, shippingInfo, card_info)
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    guest_id,
                    customer_name,
                    total,
                    payment_type,
                    JSON.stringify(shipping_address),
                    JSON.stringify(shipping_info),
                    JSON.stringify(card_info)
                ]
            );

            const orderId = orderResult.insertId;

            // Insert order items
            for (const item of items) {
                await db.query(
                    `INSERT INTO orderitems 
                    (order_id, product_id, quantity, price)
                    VALUES (?, ?, ?, ?)`,
                    [orderId, item.product_id, item.quantity, item.price]
                );
            }

            // Commit transaction
            // await db.commit();

            res.status(201).json({
                success: true,
                order_id: orderId,
                total_amount: total
            });

        } catch (err) {
            // Rollback on error
            // await db.rollback();
            throw err;
        }

    } catch (error) {
        console.error('Order error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to create order',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});
// Get the most recently created guest
app.get('/api/guests/latest', async (req, res) => {
    const connection = await db.getConnection();
    try {
        const [rows] = await connection.query(
            'SELECT * FROM guest ORDER BY created_at DESC LIMIT 1'
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'No guests found' });
        }

        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching latest guest:', error);
        res.status(500).json({ error: 'Server error' });
    } finally {
        connection.release();
    }
});
// Get customer by ID
// Get single customer by ID
app.get('/api/customers/:id', async (req, res) => {
    const customerId = req.params.id;
    try {
        const [rows] = await db.query('SELECT * FROM customers WHERE id = ?', [customerId]);
        if (rows.length === 0) return res.status(404).json({ error: 'Customer not found' });
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching customer:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/ordersCustomer', async (req, res) => {
    const {
        customer_id,
        customer_name, // ✅ NEW
        guest_id,
        total_amount,
        payment_type,
        items,
        shipping_address,
        shipping_info,
        card_info
    } = req.body;

    if (!customer_id || !Array.isArray(items) || !total_amount) {
        return res.status(400).json({ error: "Missing required data" });
    }

    try {
        const [orderResult] = await db.query(
            `INSERT INTO onlineorders 
          (customer_id, customer_name, guest_id, total_amount, payment_type, shipping_address, shippingInfo, card_info)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                customer_id,
                customer_name || null, // ✅ pass it here
                guest_id,
                total_amount,
                payment_type,
                JSON.stringify(shipping_address),
                JSON.stringify(shipping_info),
                JSON.stringify(card_info || {})
            ]
        );

        const orderId = orderResult.insertId;

        for (const item of items) {
            await db.query(
                `INSERT INTO orderitems (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)`,
                [orderId, item.product_id, item.quantity, item.price]
            );
        }

        res.status(201).json({ success: true, order_id: orderId });
    } catch (error) {
        console.error('Order error:', error);
        res.status(500).json({ error: 'Failed to place order' });
    }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// console.log('Serving static files from:', path.join(__dirname, 'uploads'));

app.get('/api/slider', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT id, title, image, status FROM slider');
        rows.forEach(row => {
            if (row.image) {
                row.image = row.image.replace(/\\/g, '/'); // Replace backslashes with forward slashes
            }
        });


        res.status(200).json(rows);

    } catch (err) {
        console.error('Error fetching sliders:', err.message);
        res.status(500).json({ message: 'Error fetching sliders', error: err.message });
    }
});

app.get('/api/products', async (req, res) => {
    console.log('➡️ API Endpoint /api/products Hit');

    const { category, brand, minPrice, maxPrice, search, discount } = req.query;

    try {
        let query = `
            SELECT 
                p.id, 
                p.name, 
                p.slug, 
                p.selling_price, 
                p.discount, 
                p.offer_price,
                p.image_path, 
                p.image_paths, 
                p.status,
                p.specifications, 
                p.details,
                c.name AS category_name,
                b.name AS brand_name
            FROM products p
            LEFT JOIN product_categories c ON p.category = c.id
            LEFT JOIN  product_brands b ON p.brand = b.id
            WHERE p.status = 'Active'
        `;
        const params = [];

        if (category) {
            query += ` AND c.name = ?`;
            params.push(category);
        }

        if (brand) {
            query += ` AND b.name = ?`;
            params.push(brand);
        }

        if (search) {
            query += ` AND (p.name LIKE ? OR b.name LIKE ?)`;
            const searchPattern = `%${search}%`;
            params.push(searchPattern, searchPattern);
        }

        if (minPrice) {
            query += ` AND p.selling_price >= ?`;
            params.push(minPrice);
        }

        if (maxPrice) {
            query += ` AND p.selling_price <= ?`;
            params.push(maxPrice);
        }

        if (discount) {
            query += ` AND p.discount >= ?`;
            params.push(discount);
        }

        query += ' LIMIT 20';
        const [rows] = await db.query(query, params);

        rows.forEach((row) => {
            if (row.image_path) {
                row.image_path = row.image_path.replace(/\\/g, '/');
            }
            if (row.image_paths) {
                try {
                    row.image_paths = JSON.parse(row.image_paths).map(p => p.replace(/\\/g, '/'));
                } catch (e) {
                    row.image_paths = [];
                }
            }
        });

        res.status(200).json({
            products: rows,
            totalCount: rows.length,
        });

    } catch (err) {
        console.error('❌ Error fetching products:', err.message);
        res.status(500).json({ message: 'Error fetching products', error: err.message });
    }
});
app.get('/api/products/discount', async (req, res) => {
    console.log('➡️ API Endpoint /api/products Hit');

    const { category, brand, minPrice, maxPrice, search } = req.query;

    try {
        let query = `
            SELECT 
                p.id, 
                p.name, 
                p.slug, 
                p.selling_price, 
                p.discount, 
                p.offer_price,
                p.image_path, 
                p.image_paths, 
                p.status,
                p.specifications, 
                p.details,
                c.name AS category_name,
                b.name AS brand_name
            FROM products p
            LEFT JOIN product_categories c ON p.category = c.id
            LEFT JOIN product_brands b ON p.brand = b.id
            WHERE p.status = 'Active' AND p.discount > 0
        `;
        const params = [];

        if (category) {
            query += ` AND c.name = ?`;
            params.push(category);
        }

        if (brand) {
            query += ` AND b.name = ?`;
            params.push(brand);
        }

        if (search) {
            query += ` AND (p.name LIKE ? OR b.name LIKE ?)`;
            const searchPattern = `%${search}%`;
            params.push(searchPattern, searchPattern);
        }

        if (minPrice) {
            query += ` AND p.selling_price >= ?`;
            params.push(minPrice);
        }

        if (maxPrice) {
            query += ` AND p.selling_price <= ?`;
            params.push(maxPrice);
        }

        query += ' LIMIT 20';
        const [rows] = await db.query(query, params);

        rows.forEach((row) => {
            if (row.image_path) {
                row.image_path = row.image_path.replace(/\\/g, '/');
            }
            if (row.image_paths) {
                try {
                    row.image_paths = JSON.parse(row.image_paths).map(p => p.replace(/\\/g, '/'));
                } catch (e) {
                    row.image_paths = [];
                }
            }
        });

        res.status(200).json({
            products: rows,
            totalCount: rows.length,
        });

    } catch (err) {
        console.error('❌ Error fetching products:', err.message);
        res.status(500).json({ message: 'Error fetching products', error: err.message });
    }
});

app.get('/api/filters', async (req, res) => {
    console.log('➡️ API Endpoint /api/filters Hit');

    try {
        const categoriesQuery = `SELECT DISTINCT category FROM products WHERE status = 'Active'`;
        const brandsQuery = `SELECT DISTINCT brand FROM products WHERE status = 'Active'`;

        const [categories] = await db.query(categoriesQuery);
        const [brands] = await db.query(brandsQuery);

        res.status(200).json({
            categories: categories.map((category) => category.category),
            brands: brands.map((brand) => brand.brand),
        });
    } catch (err) {
        console.error('❌ Error fetching filters:', err.message);
        res.status(500).json({ message: 'Error fetching filters', error: err.message });
    }
});

app.get('/api/products/:slug', async (req, res) => {
    const productId = req.params.slug;
    try {
        const [rows] = await db.query('SELECT * FROM products WHERE slug = ?', [productId]);
        // console.log([rows],"slug.....");

        if (rows.length > 0) {
            res.status(200).json(rows[0]);
        } else {
            res.status(404).json({ message: 'Product not found' });
        }
    } catch (err) {
        console.error('Error fetching product details:', err);
        res.status(500).json({ message: 'Error fetching product details', error: err.message });
    }
});

app.get('/api/product-counts', async (req, res) => {
    console.log('➡️ API Endpoint /api/product-counts Hit');

    try {
        const [rows] = await db.query(`
            SELECT pc.name AS category, COUNT(p.id) AS product_count
            FROM products p
            JOIN product_categories pc ON p.category = pc.id
            WHERE p.status = 'Active'
            GROUP BY pc.name
        `);

        // console.log('✅ Database Query Successful, Counts Fetched:', rows);

        res.status(200).json({ categoryCounts: rows });
    } catch (err) {
        console.error('❌ Error fetching category counts:', err.message);
        res.status(500).json({ message: 'Error fetching category counts', error: err.message });
    }
});

app.get('/api/product-categories', async (req, res) => {
    console.log('➡️ API Endpoint /api/product-categories Hit');

    try {
        const [rows] = await db.query(`
            SELECT id, name, image_path
            FROM product_categories
            WHERE status = 'Active'
        `);

        // console.log('✅ Categories Fetched:', rows);
        res.status(200).json({ categories: rows });
    } catch (err) {
        console.error('❌ Error fetching product categories:', err.message);
        res.status(500).json({ message: 'Error fetching product categories', error: err.message });
    }
});

app.get('/api/product-brands', async (req, res) => {
    try {
        const sql = `
            SELECT name, image_path, status
            FROM product_brands
            WHERE status = 'Active'
        `;
        const [rows] = await db.query(sql);

        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching product brands:', err.message);
        res.status(500).json({ message: 'Error fetching product brands' });
    }
});

app.get('/api/country-codes', async (req, res) => {
    try {
        const query = `
            SELECT country_name, dialing_code 
            FROM country_codes
            ORDER BY country_name ASC
        `;
        const [rows] = await db.query(query);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'No country codes found.' });
        }

        res.status(200).json(rows);
    } catch (err) {
        console.error('Error fetching country codes:', err.message);
        res.status(500).json({ message: 'Error fetching country codes' });
    }
});

app.post('/api/save-guest', (req, res) => {
    const { guestId } = req.body;
    if (!guestId) return res.status(400).json({ error: "Guest ID is required" });

    const query = "INSERT INTO guests (guest_id) VALUES (?)";
    db.query(query, [guestId], (err, result) => {
        if (err) {
            console.error("Database Error:", err);
            res.status(500).json({ error: "Database error" });
        } else {
            res.status(201).json({ message: "Guest ID saved successfully" });
        }
    });
});

app.post('/api/coupons/validate', async (req, res) => {
    const { code, cartTotal } = req.body;

    try {
        // Get coupon from database
        const [coupon] = await db.query(
            'SELECT * FROM coupons WHERE code = ? AND NOW() BETWEEN start_date AND end_date',
            [code]
        );

        if (!coupon.length) {
            return res.status(400).json({ message: 'Invalid or expired coupon' });
        }

        const couponData = coupon[0];

        // Check minimum order amount
        if (cartTotal < couponData.min_order_amount) {
            return res.status(400).json({
                message: `Minimum order amount of AED ${couponData.min_order_amount} required`
            });
        }

        // Check usage limits (you'll need a coupon_usage table for proper tracking)
        const [usage] = await db.query(
            'SELECT COUNT(*) AS count FROM coupon_usage WHERE coupon_id = ? AND user_id = ?',
            [couponData.id, req.user.id] // Add user authentication if needed
        );

        if (usage[0].count >= couponData.limit_per_user) {
            return res.status(400).json({ message: 'Coupon usage limit reached' });
        }

        res.json({
            valid: true,
            coupon: {
                id: couponData.id,
                code: couponData.code,
                discount: couponData.discount,
                discount_type: couponData.discount_type,
                max_discount: couponData.max_discount
            }
        });

    } catch (error) {
        console.error('Coupon validation error:', error);
        res.status(500).json({ message: 'Error validating coupon' });
    }
});

// Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
