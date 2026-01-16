import { StatusCodes } from "http-status-codes";
import { User } from "../models/user.model.js";
import { verifyAccessToken } from "../lib/token.js";

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: "Authentication token missing or invalid" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = verifyAccessToken(token);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ message: "User not found" });
    }

    if (user.tokenVersion !== payload.version) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ message: "Token has been revoked" });
    }

    const authReq = req;
    authReq.user = {
      id: user._id,
      email: user.email,
      role: user.role,
      name: user.name,
      isEmailVerified: user.isEmailVerified,
    };

    next();
  } catch (error) {
    console.log(error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: "Internal server error.",
      error: error.message,
    });
  }
}

export default requireAuth;
