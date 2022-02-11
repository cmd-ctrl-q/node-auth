import { Request, Response } from 'express';
import { getRepository } from 'typeorm';
import { User } from '../entity/user.entity';
import bcryptjs from 'bcryptjs';
import { sign, verify } from 'jsonwebtoken';

export const Register = async (req: Request, res: Response) => {
  const { first_name, last_name, email, password, password_confirm } = req.body;

  // check if password matches
  if (password !== password_confirm) {
    return res
      .status(400)
      .send({ ok: false, message: "Password's do not match!" });
  }

  // check if user already exists
  const exists = await getRepository(User).findOne({ email });
  if (exists) {
    return res.status(400).send({ ok: false, message: 'User already exists!' });
  }

  // hash password
  const hash = await bcryptjs.hash(password, 12);

  const user = await getRepository(User).save({
    first_name: first_name,
    last_name: last_name,
    email: email,
    password: hash,
  });

  res.send({ ok: true, user });
};

export const Login = async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = await getRepository(User).findOne({ email });

  if (!user) {
    return res.status(404).send({ ok: false, message: 'Invalid credentials' });
  }

  // check if password is correct
  if (!(await bcryptjs.compare(password, user.password))) {
    return res.status(400).send({ ok: false, message: 'Invalid credentials' });
  }

  // create 30 second access token
  const accessToken = sign(
    {
      id: user.id, // payload stored in jwt
    },
    process.env.ACCESS_SECRET || '',
    { expiresIn: '30s' }
  );

  // create 7 day refresh token
  const refreshToken = sign(
    {
      id: user.id, // payload stored in jwt
    },
    process.env.REFRESH_SECRET || '',
    { expiresIn: '1w' }
  );

  // store access token in cookie
  res.cookie('access_token', accessToken, {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  });

  // store refresh token in cookie
  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  res.send({ ok: true, message: 'success' });
};

export const AuthenticatedUser = async (req: Request, res: Response) => {
  try {
    // get access_token cookie
    const cookie = req.cookies['access_token'];

    const payload: any = verify(cookie, process.env.ACCESS_SECRET || '');

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

    const { password, ...data } = user;

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

    // create access token
    const accessToken = sign(
      {
        id: payload.id, // payload id stored in jwt
      },
      process.env.ACCESS_SECRET || '',
      { expiresIn: '30s' }
    );

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 days
    });

    return res.send({ message: 'success' });
  } catch (err) {
    return res.status(401).send({
      message: 'unauthenticated',
    });
  }
};

export const Logout = async (req: Request, res: Response) => {
  // delete cookie
  res.cookie('access_token', { maxAge: 0 });
  res.cookie('refresh_token', { maxAge: 0 });

  res.redirect('localhost:8000/login');

  // res.send({
  //   message: 'successfully deleted cookie',
  // });
};
