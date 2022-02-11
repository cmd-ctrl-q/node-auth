require('dotenv').config();

import express, { Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { createConnection } from 'typeorm';
import { routes } from './routes';

createConnection().then(() => {
  const app = express();

  // convert each request to json
  app.use(express.json());
  app.use(cookieParser());
  app.use(
    cors({
      origin: [
        'http://localhost:3000', // react
        'http://localhost:8080', // vue
        'http://localhost:4200', // angular
      ],
      credentials: true, // allow sending and receiving cookies
    })
  );

  // routes
  routes(app);

  app.listen(8000, () => {
    console.log('Listening on port 8000');
  });
});
