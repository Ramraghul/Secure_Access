import { Request, Response } from "express";
export const authorize = (req: Request, res: Response) => {
  const { response_type, client_id, redirect_uri, state } = req.query;
  if (response_type !== "code" || !client_id || !redirect_uri) {
    res.status(400).json({ error: "invalid_request" }); return;
  }
  const code = Buffer.from(JSON.stringify({ userId: "demo-user", client_id })).toString("base64url");
  res.redirect(`${redirect_uri}?code=${code}&state=${state ?? ""}`);
};
