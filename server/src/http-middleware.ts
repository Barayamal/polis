import compression from "compression";
import cookieParser from "cookie-parser";
import express, { NextFunction, Request, Response } from "express";

const REQUEST_BODY_LIMIT = "50mb";

export function rejectUnsupportedMultipart(
  req: Request,
  res: Response,
  next: NextFunction
) {
  if (!req.is("multipart/form-data")) {
    return next();
  }

  return res.status(415).json({
    error: "polis_err_multipart_not_supported",
    message: "polis_err_multipart_not_supported",
    status: 415,
  });
}

export function createJsonBodyParser() {
  return express.json({
    limit: REQUEST_BODY_LIMIT,
    type: ["application/json", "application/*+json"],
  });
}

export function createUrlencodedBodyParser() {
  return express.urlencoded({
    extended: true,
    limit: REQUEST_BODY_LIMIT,
  });
}

export function createCookieParser() {
  return cookieParser();
}

export function createResponseCompression() {
  return compression();
}
