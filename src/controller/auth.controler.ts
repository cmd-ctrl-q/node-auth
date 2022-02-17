import { Request, Response } from 'express';
import { getRepository, MoreThanOrEqual } from 'typeorm';
import { User } from '../entity/user.entity';
import bcryptjs from 'bcryptjs';
import { sign, verify } from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import { OAuth2Client } from 'google-auth-library';
import { Token } from '../entity/token.entity';

export const Register = async (req: Request, res: Response) => {
  const body = req.body;

  // check if password matches
  if (body.password !== body.password_confirm) {
    return res
      .status(400)
      .send({ ok: false, message: "Password's do not match!" });
  }

  // check if user already exists
  const exists = await getRepository(User).findOne({ email: body.email });
  if (exists) {
    return res.status(400).send({ ok: false, message: 'User already exists!' });
  }

  const { password, tfa_secret, ...user } = await getRepository(User).save({
    first_name: body.first_name,
    last_name: body.last_name,
    email: body.email,
    password: await bcryptjs.hash(body.password, 12),
  });

  res.send({ ok: true, user });
};

export const Login = async (req: Request, res: Response) => {
  const user = await getRepository(User).findOne({ email: req.body.email });

  if (!user) {
    return res.status(404).send({ ok: false, message: 'Invalid credentials' });
  }

  // check if password is correct
  if (!(await bcryptjs.compare(req.body.password, user.password))) {
    return res
      .status(400)
      .send({ ok: false, message: 'Invalid credentials 2' });
  }

  // two factor auth
  if (user.tfa_secret) {
    return res.send({ id: user.id });
  }

  // if not set, generate secret
  const secret = speakeasy.generateSecret({
    name: 'My App', // name in QR code
  });

  res.send({
    id: user.id,
    secret: secret.ascii,
    otpauth_url: secret.otpauth_url, // generate QR code
  });
};

export const TwoFactor = async (req: Request, res: Response) => {
  try {
    const id = req.body.id;

    const repository = getRepository(User);

    const user = await repository.findOne(id);

    if (!user) {
      return res.status(400).send({
        ok: false,
        message: 'Invalid credentials',
      });
    }

    // get secret (from request, or db)
    const secret = user.tfa_secret !== '' ? user.tfa_secret : req.body.secret;

    // verify QR code
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'ascii',
      token: req.body.code, // code from auth indicatory
    });

    if (!verified) {
      return res.status(400).send({
        ok: false,
        message: 'Invalid credentials',
      });
    }

    // update the tfa_secret if non-existent
    if (user.tfa_secret === '') {
      await repository.update(id, { tfa_secret: secret });
    }

    // if QR code is valid, continue to create access and refresh tokens

    // create 7 day refresh token
    const refreshToken = sign(
      {
        id: user.id, // payload stored in jwt
      },
      process.env.REFRESH_SECRET || '',
      { expiresIn: '1w' }
    );

    // store refresh token in cookie
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    const expired_at = new Date();
    expired_at.setDate(expired_at.getDate() + 7);

    // save token
    await getRepository(Token).save({
      user_id: id,
      token: refreshToken,
      expired_at,
    });

    // create 30 second access token
    const token = sign(
      {
        id: user.id, // payload stored in jwt
      },
      process.env.ACCESS_SECRET || '',
      { expiresIn: '30s' }
    );

    res.send({ ok: true, token });
  } catch (err) {
    return res.status(401).send({
      message: 'unauthenticated',
    });
  }
};

export const AuthenticatedUser = async (req: Request, res: Response) => {
  try {
    // get access token from authorization header
    const accessToken = req.header('Authorization')?.split(' ')[1] || '';

    const payload: any = verify(accessToken, process.env.ACCESS_SECRET || '');

    if (!payload) {
      return res.status(401).send({
        message: 'unauthenticated',
      });
    }

    const user = await getRepository(User).findOne(payload.id);

    if (!user) {
      return res.status(401).send({
        message: 'unauthenticated',
      });
    }

    const { password, tfa_secret, ...data } = user;

    res.send(data);
  } catch (err) {
    return res.status(401).send({
      message: 'unauthenticated',
    });
  }
};

//
export const Refresh = async (req: Request, res: Response) => {
  try {
    const cookie = req.cookies['refresh_token'];

    const payload: any = verify(cookie, process.env.REFRESH_SECRET || '');

    if (!payload) {
      return res.status(401).send({
        message: 'unauthenticated',
      });
    }

    const refreshToken = await getRepository(Token).findOne({
      user_id: payload.id,
      expired_at: MoreThanOrEqual(new Date()),
    });

    if (!refreshToken) {
      return res.status(401).send({
        message: 'unauthenticated',
      });
    }

    // create access token
    const token = sign(
      {
        id: payload.id, // payload id stored in jwt
      },
      process.env.ACCESS_SECRET || '',
      { expiresIn: '30s' }
    );

    return res.send({ token, message: 'success' });
  } catch (err) {
    return res.status(401).send({
      message: 'unauthenticated',
    });
  }
};

export const Logout = async (req: Request, res: Response) => {
  // delete refresh token from db
  await getRepository(Token).delete({
    token: req.cookies['refresh_token'],
  });

  // delete refresh token from cookie
  res.cookie('refresh_token', { maxAge: 0 });

  res.send({
    message: 'successfully deleted cookie',
  });
};

export const GoogleAuth = async (req: Request, res: Response) => {
  // google auth token
  const { token } = req.body;

  // verify token
  const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

  // get ticket
  const ticket = await client.verifyIdToken({
    idToken: token,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  // get payload
  const payload = ticket.getPayload();

  if (!payload) {
    return res.status(401).send({
      message: 'unauthenticated',
    });
  }

  const repository = getRepository(User);

  let user = await repository.findOne({ email: payload.email });

  // if no user, create new user
  if (!user) {
    user = await repository.save({
      first_name: payload.given_name,
      last_name: payload.family_name || '',
      email: payload.email,
      password: await bcryptjs.hash(token, 12),
    });
  }

  // create 7 day refresh token
  const refreshToken = sign(
    {
      id: user.id, // payload stored in jwt
    },
    process.env.REFRESH_SECRET || '',
    { expiresIn: '1w' }
  );

  // store refresh token in cookie
  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  const expired_at = new Date();
  expired_at.setDate(expired_at.getDate() + 7);

  // save token
  await getRepository(Token).save({
    user_id: user.id,
    token: refreshToken,
    expired_at,
  });

  // create and send 30 second access token
  res.send({
    message: sign(
      {
        id: user.id, // payload stored in jwt
      },
      process.env.ACCESS_SECRET || '',
      { expiresIn: '30s' }
    ),
  });
};
