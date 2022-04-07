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
    try {
      if (!req.headers["authorization"]) throw new Error("No authorization header");

      const matches = req.headers["authorization"].match(/Bearer ([\w_\-=]*\.[\w_\-=]*\.[\w_\-=]*)/);

      if (!matches) throw new Error("Token does not match expected format");

      req.user = decode(matches[1], { json: true });

      next();
    } catch (e: any) {
      res.sendStatus(401);
    }
  }

export default authorize;
