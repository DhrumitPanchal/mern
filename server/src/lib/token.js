import jwt from "jsonwebtoken";

export function generateAccessToken(id, role, version) {
  const payload = {
    sub: id,
    role,
    version,
  };

  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, { expiresIn: "15m" });
}

export function generateRefreshToken(id, version) {
  const payload = {
    sub: id,
    version,
  };

  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: "4d",
  });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
}

export function verifyRefreshToken(token) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
}
