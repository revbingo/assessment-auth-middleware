import nock from "nock";
import { createRequest, createResponse } from "node-mocks-http";
import authorise from "./index";
import TokenGenerator from "./__tests__/TokenGenerator";

const tokenGenerator = new TokenGenerator();
const options = {
  issuer: "http://issuer.com",
  audience: "audience",
  algorithms: "RS256",
};
const currentTime = Math.round(Date.now() / 1000);
const claims = {
  sub: "foo",
  iss: options.issuer,
  aud: options.audience,
  exp: currentTime + 10,
};

beforeAll(async () => {
  await tokenGenerator.init();

  nock(options.issuer)
    .persist()
    .get("/.well-known/jwks.json")
    .reply(200, { keys: [tokenGenerator.jwk] });
});

describe("A request with a valid access token", () => {
  test("should add a user object containing the token claims to the request", async () => {
    const res = createResponse();
    const next = jest.fn();
    const token = await tokenGenerator.createSignedJWT(claims);
    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);
    expect(req).toHaveProperty("user", claims);
  });

  test("should call next middleware after decoding", async () => {
    const res = createResponse();
    const next = jest.fn();
    const token = await tokenGenerator.createSignedJWT(claims);
    const req = createRequest({
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await authorise(options)(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test("should send a 401 response if the token is missing", async () => {
    const res = createResponse();
    const next = jest.fn();
    const req = createRequest({
      headers: {},
    });

    await authorise(options)(req, res, next);
    expect(res._getStatusCode()).toEqual(401);
  });

  test("does not call next middleware if token is missing", async () => {
    const res = createResponse();
    const next = jest.fn();
    const req = createRequest({
      headers: {},
    });

    await authorise(options)(req, res, next);
    expect(next).not.toHaveBeenCalled();
  });
});
