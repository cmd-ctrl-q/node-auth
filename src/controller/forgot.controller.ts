import { Request, Response } from 'express';
import { createTransport } from 'nodemailer';
import { getRepository } from 'typeorm';
import bcryptjs from 'bcryptjs';
import { Reset } from '../entity/reset.entity';
import { User } from '../entity/user.entity';

export const ForgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;

  // url string for resetting password
  const token = Math.random().toString(20).substring(2, 12);

  // store token in db
  await getRepository(Reset).save({
    email,
    token,
  });

  const transporter = createTransport({
    host: '0.0.0.0',
    port: 1025,
  });

  // generate a new url with the random url string
  const url = `http://localhost:3000/reset/${token}`;

  // send email
  await transporter.sendMail({
    from: 'from@example.com',
    to: email,
    subject: 'Reset your password!',
    html: `Click <a href=${url}>here</a> to reset your password`,
  });

  res.send({
    message: 'Please check your email',
  });
};

export const ResetPassword = async (req: Request, res: Response) => {
  // get token from url
  const { token, password, password_confirm } = req.body;

  // check if password matches
  if (password !== password_confirm) {
    return res.status(400).send({ message: "Password's do not match!" });
  }

  // get token from db
  const resetPassword = await getRepository(Reset).findOne({ token });

  // check if the token exists
  if (!resetPassword) {
    return res.status(400).send({ message: 'Invalid url!' });
  }

  // link is valid
  const user = await getRepository(User).findOne({
    email: resetPassword.email,
  });

  if (!user) {
    return res.status(400).send({ message: 'User not found!' });
  }

  // update password
  await getRepository(User).update(user.id, {
    password: await bcryptjs.hash(password, 12),
  });

  // delete password from db
  await getRepository(Reset).delete({ token });

  res.send({
    message: 'successfully changed password',
  });
};
