import express from 'express';
import bodyParser from 'body-parser';
import Datastore from 'nedb-promises';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { accessTokenSecret, refreshTokenSecret, accessTokenExpiresIn, refreshTokenExpiresIn, cacheTemporaryTokenPrefix, cacheTemporaryTokenExpiresInSeconds } from './config.js';
import { authenticator } from 'otplib'
import qrcode from 'qrcode'
import crypto from 'crypto';
import NodeCache from 'node-cache';
const app = express();


app.use(bodyParser.json())

/**
 * Use a temporary cache and database for testing purposes only.
 */
const cache = new NodeCache()
const users = Datastore.create('Users.db')
const userRefreshTokens = Datastore.create('UserRefreshToken.db')
const userInvalidTokens = Datastore.create('UserInvalidTokens.db')

app.get('/', (req, res) => {
    res.send('Rest api auth');
});

/**
 * Registration
 * Only need a basic informatoin such as name, email, password and role
 * the role property is optional by default the role is set to member
 * the 2faEnable is set to false by default
 * the 2faSecret is set to null by default
 */
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        if (!name || !email || !password) {
            return res.status(422).json({ message: 'Please fill in all fields.' });
        }

        if (await users.findOne({ email: email })) {
            return res.status(409).json({ message: 'Email already exists.' })
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await users.insert({
            name: name,
            email: email,
            password: hashedPassword,
            role: role ?? 'member',
            '2faEnable': false,
            '2faSecret': null
        })

        return res.status(201).json({
            message: 'User registered successfully',
            id: newUser._id,
            password: newUser.password
        });

    } catch (error) {
        return res.status(500).json({
            message: error.message,

        });
    }
});


/**
 * Always remember to set the refresh token expiration higher than the access token
 * LOGIN
 * this login route have a two response depends on what kind of user login use.
 * When the user 2faEnable is set to false then it will return the basic info , access token and the refreshToken
 * WHen the user 2faEnable is set to true then it will return a tempToken and expiration then it will save to cache temporary
 * 
 */
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(422).json({ message: 'Please fill in all fields' });
        }

        const user = await users.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: 'Email or Password is invalid' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Email or password is invalid' });
        }

        if (user['2faEnable']) {
            const tempToken = crypto.randomUUID();
            cache.set(cacheTemporaryTokenPrefix + tempToken, user._id, cacheTemporaryTokenExpiresInSeconds);
            return res.status(200).json({ tempToken, expiresInSeconds: cacheTemporaryTokenExpiresInSeconds })

        } else {

            const accessToken = jwt.sign({ userId: user._id }, accessTokenSecret, { subject: 'accessApi', expiresIn: accessTokenExpiresIn });
            const refreshToken = jwt.sign({ userId: user._id }, refreshTokenSecret, { subject: 'refreshToken', expiresIn: refreshTokenExpiresIn });
            await userRefreshTokens.insert({
                refreshToken: refreshToken,
                userId: user._id
            });


            return res.status(200).json({
                id: user._id,
                name: user.name,
                email: user.email,
                accessToken: accessToken,
                refreshToken
            })
        }


    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});


/**
 * 2FA Login
 *  The 2fa login required the tempToken and totp(TIME-BASED ONE-TIME PASSWORD)
 * Get the temptoken in the login response when the user enabled the 2fa 
 * Get the totp from the authenticator app (Google Authenticator(PlayStore))
 */
app.post('/api/auth/login/2fa', async (req, res) => {
    try {
        const { tempToken, totp } = req.body

        if (!tempToken || !totp) {
            return res.status(422).json({ message: 'Please fill in all fields' });
        }

        const userID = cache.get(cacheTemporaryTokenPrefix + tempToken);
        if (!userID) {
            return res.status(401).json({ message: 'The provided temporary token is incorrect or expired' })
        }

        const user = await users.findOne({ _id: userID });
        const verified = authenticator.check(totp, user['2faSecret']);
        if (!verified) {
            return res.status(401).json({ message: 'The provided topt is incorrect or expired' })
        }

        const accessToken = jwt.sign({ userId: user._id }, accessTokenSecret, { subject: 'accessApi', expiresIn: accessTokenExpiresIn });
        const refreshToken = jwt.sign({ userId: user._id }, refreshTokenSecret, { subject: 'refreshToken', expiresIn: refreshTokenExpiresIn });
        await userRefreshTokens.insert({
            refreshToken: refreshToken,
            userId: user._id
        });


        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email,
            accessToken: accessToken,
            refreshToken
        })

    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
})

/**
 * Refresh token
 * The refresh token have a separate table and save all the refresh token base on user id
 */
app.post('/api/auth/refresh-token', async (req, res) => {
    try {

        const { refreshToken } = req.body

        if (!refreshToken) {
            return res.status(401).json({ message: 'Refresh token not found' })
        }

        const decodedRefreshToken = jwt.verify(refreshToken, refreshTokenSecret);

        const userRefreshToken = await userRefreshTokens.findOne({ refreshToken: refreshToken, userId: decodedRefreshToken.userId });
        if (!userRefreshToken) {
            return res.status(401).json({ message: 'Refresh token invalid or expired' });
        }

        await userRefreshTokens.remove({ _id: userRefreshToken._id });
        await userRefreshTokens.compactDatafile();


        const accessToken = jwt.sign({ userId: decodedRefreshToken.userId }, accessTokenSecret, { subject: 'accessApi', expiresIn: accessTokenExpiresIn });

        const newRefreshToken = jwt.sign({ userId: decodedRefreshToken.userId }, refreshTokenSecret, { subject: 'refreshToken', expiresIn: refreshTokenExpiresIn });

        await userRefreshTokens.insert({
            refreshToken: userRefreshTokens,
            userId: decodedRefreshToken.userId
        });


        return res.status(200).json({
            accessToken: accessToken,
            refreshToken: newRefreshToken
        })

    } catch (error) {
        if (error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ message: 'Refresh token invalid or expired' });
        }
        return res.status(500).json({ message: error.message })
    }
})


/**
 * Auth middleware
 * 
 */
const auth = async (req, res, next) => {
    const auth = req.headers.authorization

    if (!auth) {
        return res.status(401).json({ message: 'Access token not found' });
    }

    const accessToken = auth.startsWith('Bearer ') ? auth.slice(7) : auth;

    if (await userInvalidTokens.findOne({ accessToken: accessToken })) {
        return res.status(401).json({ message: 'Access token invalid', code: 'AccessTokenInvalid' });
    }

    try {
        const decodeAccessToken = jwt.verify(accessToken, accessTokenSecret);

        req.accessToken = { value: accessToken, exp: decodeAccessToken.exp }
        req.user = { id: decodeAccessToken.userId }

        next();

    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ message: 'Access token expired', code: 'AccessTokenExpired' });
        } else if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ message: 'Access token invalid', code: 'AccessTokenInvalid' });
        } else {
            return res.status(500).json({ message: error.message })
        }
    }
}


/**
 * Authorize Midleware 
 * this middleware check the roles of current login user
 */
const authorize = (roles = []) => {
    return async (req, res, next) => {
        const user = await users.findOne({ _id: req.user.id });

        if (!user || !roles.includes(user.role)) {
            return res.status(403).json({ message: 'Access denied' });
        }

        next();

    }
}

/** Protected routes
 *  All routes below the app.use(auth) is protected
 */
app.use(auth);

/**
 * 2fa Generate
 * this route will generate a 2fa qr code that could use in the client side and the user will scan the qr code
 * when the user scan the qr code, they will redirect to any authenticator that has been installed in their devices
 * this will also gnerate and set the secret for a specific user
 * that generated secret will be the fix secret of the user
 */
app.get('/api/auth/2fa/generate', async (req, res) => {

    try {
        const user = await users.findOne({ _id: req.user.id });
        const secret = authenticator.generateSecret()
        const uri = authenticator.keyuri(user.email, 'lay-bare.com', secret);

        await users.update({ _id: user._id }, { $set: { '2faSecret': secret } });
        await users.compactDatafile();
        const qrCode = await qrcode.toBuffer(uri, { type: 'image/png', margin: 1 })

        res.setHeader('Content-Disposition', 'attachment; filename=qrcode.png')

        return res.status(200).type('image/png').send(qrCode);


    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

/**
 * 2fa Validation
 * this route will help the client side to validate if the totp is valid
 */
app.post('/api/auth/2fa/validate', async (req, res) => {
    try {
        const { totp } = req.body


        if (!totp) {
            return res.status(422).json({ message: 'TOTP is required' });
        }

        const user = await users.findOne({ _id: req.user.id });
        const verify = authenticator.check(totp, user['2faSecret']);

        if (!verify) {
            return res.status(400).json({ message: 'TOTP is not correct or expired' });
        }

        await users.update({ _id: req.user.id }, { $set: { '2faEnable': true } });

        await users.compactDatafile();

        return res.status(200).json({ message: 'TOTPT validated sucessfully' });

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
})

/**
 * Logout
 * instead of just deleting the tokens or revoke
 * there is a separate table to store all accesstokens of each users
 * when the logout the accesstoken, userId and expirationTime will inserted to that database table
 * so that the middleware always check if the token is invalid or already logout
 * create a cron job that will auto delete all the expired accesstoken that is the reason why the expirationTime is also included
 */

app.post('/api/auth/logout', async (req, res) => {

    try {

        const { refreshToken } = req.body;

        // logout all
        await userRefreshTokens.removeMany({ userId: req.user.id });
        await userRefreshTokens.compactDatafile();

        // logout one device
        // await userRefreshTokens.remove({ refreshToken: refreshToken });

        await userInvalidTokens.insert({
            accessToken: req.accessToken.value,
            userId: req.user.id,
            expirationTime: req.accessToken.exp
        });

        return res.status(204).send();

    } catch (error) {
        return res.status(500).json({ message: error.message })
    }

})

/**
 * For testing routes
 */
app.get('/api/users/current', async (req, res) => {
    try {
        const user = await users.findOne({ _id: req.user.id });

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email
        });

    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
})

app.get('/api/admin', authorize(['admin']), async (req, res) => {
    return res.status(200).json({ message: 'Only admins can access this route' })
})

app.get('/api/moderator', authorize(['admin', 'moderator']), async (req, res) => {
    return res.status(200).json({ message: 'Only admins and moderators can access this route' })
})



app.listen(4000, () => {
    console.log("Server start at port 4000");
});