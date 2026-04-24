// src/utils/jwt.ts
import jwt, { SignOptions } from "jsonwebtoken";
import { config } from "../config";

export interface JwtPayload {
  id:       string;
  email?:   string;
  deviceId?: string;
  type:     "access" | "refresh" | "one-time";
  iat?:     number;
  exp?:     number;
}

const opts = (expiresIn: string | number): SignOptions => ({
  expiresIn: expiresIn as SignOptions["expiresIn"],
  algorithm: "HS512",
});

export const signJwt = (
  payload: Omit<JwtPayload, "iat" | "exp" | "type">,
  expiresIn: string | number = config.jwt.expiresIn
): string =>
  jwt.sign({ ...payload, type: "access" }, config.jwt.secret, opts(expiresIn));

export const verifyJwt = (token: string): JwtPayload =>
  jwt.verify(token, config.jwt.secret, { algorithms: ["HS512"] }) as JwtPayload;

export const signRefreshToken = (userId: string, deviceId?: string): string =>
  jwt.sign({ id: userId, deviceId, type: "refresh" }, config.jwt.secret, opts("30d"));

export const signOneTimeToken = (payload: object, expiresIn: string | number = "10m"): string =>
  jwt.sign({ ...payload, type: "one-time" }, config.jwt.secret, opts(expiresIn));

export const decodeJwt = (token: string): JwtPayload | null =>
  jwt.decode(token) as JwtPayload | null;
