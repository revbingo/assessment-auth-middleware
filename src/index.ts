import { verify, decode, JwtPayload } from "jsonwebtoken";
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
    const [_, token] = req.headers['authorization'].match(/Bearer (.*)/);

    req.user = decode(token, { json: true });
    next();
  }

export default authorize;
