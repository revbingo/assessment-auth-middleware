import { verify, decode, JwtPayload, Jwt, Algorithm, VerifyOptions } from "jsonwebtoken";
import jwksClient from 'jwks-rsa';
import * as express from "express";

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
    } catch (e: any) {
      res.sendStatus(401);
    }
  }

const fetchKey =
  (issuer: string) =>
    (header: any, callback: (err, signingKey) => void) => {
      const client = jwksClient({ jwksUri: `${issuer}/.well-known/jwks.json` });
      client.getSigningKey(header.kid, (err, key) => {
        callback(err, key.getPublicKey());
      });
    };

const verifyToken =
  async (token: string, options: Options) =>
    new Promise((resolve, reject) => {
      const verifyOptions: VerifyOptions = {
        issuer: options.issuer,
        audience: options.audience,
        algorithms: [options.algorithms as Algorithm]
      }
      verify(token, fetchKey(options.issuer), verifyOptions, (err, key) => {
        err ? reject(err) : resolve(key)
      })
    }
  );

export default authorize;
