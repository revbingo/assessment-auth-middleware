import { verify, decode, JwtPayload, Jwt, Algorithm, VerifyOptions } from "jsonwebtoken";
import jwksClient from 'jwks-rsa';
import * as express from "express";
import { promisify } from 'util';

const verifyAsync = promisify<string, any, VerifyOptions, JwtPayload>(verify);

declare module "express" {
  interface Request {
    user?: JwtPayload;
  }
}

export interface Options {
  issuer: string;
  audience: string;
  algorithms: string;
}

const authorize =
  (options: Options) =>
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ): Promise<void | express.Response> => {
    try {
      if (!req.headers["authorization"]) throw new Error("No authorization header");

      const matches = req.headers["authorization"].match(/Bearer ([\w_\-=]*\.[\w_\-=]*\.[\w_\-=]*)/);

      if (!matches) throw new Error("Token does not match expected format");

      req.user = await verifyToken(matches[1], options);

      next();
    } catch (e: unknown) {
      res.sendStatus(401);
    }
  }

const verifyToken =
  async (token: string, options: Options) => {
    const verifyOptions: VerifyOptions = {
      issuer: options.issuer,
      audience: options.audience,
      algorithms: [options.algorithms as Algorithm]
    }
    return verifyAsync(token, fetchKey(options.issuer), verifyOptions)
  }

const fetchKey =
  (issuer: string) =>
    (header: any, callback: (err, signingKey) => void) => {
      const client = jwksClient({ jwksUri: `${issuer}/.well-known/jwks.json` });
      client.getSigningKey(header.kid, (err, key) => {
        callback(err, key.getPublicKey());
      });
    };

export default authorize;
