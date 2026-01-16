import { comparePassword, hashPassword } from "../../lib/hash.js";
import { User } from "../../models/user.model.js";
import { loginSchema, registerSchema } from "./auth.schema.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import StatusCodes from "http-status-codes";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} from "../../lib/token.js";
import { sendEmail } from "../../lib/email.js";
import { OAuth2Client } from "google-auth-library";

function getAppUrl() {
  return (
    process.env.APP_URL || `http://localhost:${process.env.PORT || 4000}/api`
  );
}

function getGoogleClient() {
  const clientId = process.env.OATH_GOOGLE_CLIENT_ID;
  const clientSecret = process.env.OATH_GOOGLE_CLIENT_SECRET;
  const redirectUrl = process.env.OATH_GOOGLE_REDIRECT_URL;

  if (!clientId || !clientSecret || !redirectUrl) {
    throw new Error(
      "Google OAuth credentials are not set in environment variables."
    );
  }

  return new OAuth2Client({
    clientId,
    clientSecret,
    redirectUri: redirectUrl,
  });
}

export async function registerHandler(req, res) {
  try {
    const result = registerSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(StatusCodes.BAD_REQUEST).json({
        message: "Invalid data!",
        error: result.error.flatten(),
      });
    }

    const { email, name, password } = result.data;

    const normalizeEmail = email.toLocaleLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizeEmail });

    if (existingUser) {
      return res.status(StatusCodes.CONFLICT).json({
        message: "Email is already in use! please try with different email",
      });
    }

    const PasswordHash = await hashPassword(password);

    const newUser = new User({
      email: normalizeEmail,
      name,
      password: PasswordHash,
      role: "user",
      isEmailVerified: false,
    });

    await newUser.save();

    const verifyToken = jwt.sign(
      {
        sub: newUser._id,
      },
      process.env.JWT_ACCESS_SECRET,
      {
        expiresIn: "1d",
      }
    );

    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newUser.email,
      "Verify your email address",
      `<p>Click the link below to verify your email address:</p>
      <a href="${verifyUrl}">${verifyUrl}</a>
      <p>This link will expire in 24 hours.</p>`
    );

    return res.status(StatusCodes.CREATED).json({
      message: "User registered successfully! Please verify your email.",
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: "Something went wrong!",
      error: error.message,
    });
  }
}

export async function verifyEmailHandler(req, res) {
  const token = req.query.token;

  if (!token) {
    return res.status(StatusCodes.BAD_REQUEST).json({
      message: "Verification token is missing.",
    });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(StatusCodes.NOT_FOUND).json({
        message: "User not found.",
      });
    }

    if (user.isEmailVerified) {
      return res.json({
        message: "Email is already verified.",
      });
    }

    user.isEmailVerified = true;

    await user.save();

    return res.status(StatusCodes.OK).json({
      message: "Email verified successfully!",
    });
  } catch (error) {
    console.log(error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: "Internal server error.",
      error: error.message,
    });
  }
}

export async function loginHandler(req, res) {
  try {
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(StatusCodes.BAD_REQUEST).json({
        message: "Invalid data!",
        error: result.error.flatten(),
      });
    }

    const { email, password } = result.data;

    const normalizeEmail = email.toLocaleLowerCase().trim();

    const user = await User.findOne({ email: normalizeEmail });

    if (!user) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        message: "Invalid email or password.",
      });
    }

    const ok = await comparePassword(password, user.password);

    if (!ok) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        message: "Invalid email or password.",
      });
    }

    if (!user.isEmailVerified) {
      return res.status(StatusCodes.FORBIDDEN).json({
        message: "Email is not verified. Please verify your email to login.",
      });
    }

    const accessToken = generateAccessToken(
      user._id,
      user.role,
      user.tokenVersion
    );
    const refreshToken = generateRefreshToken(user._id, user.tokenVersion);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 4 * 24 * 60 * 60 * 1000, // 4 days
    });

    return res.status(StatusCodes.OK).json({
      message: "Login successful!",
      accessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: "Internal server error.",
      error: error.message,
    });
  }
}

export async function refreshHandler(req, res) {
  try {
    const token = req.cookies?.refreshToken;

    if (!token) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        message: "Refresh token is missing.",
      });
    }

    const payload = verifyRefreshToken(token);

    const user = await User.findById(payload.sub);

    if (!user) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        message: "User not found.",
      });
    }

    if (payload.version !== user.tokenVersion) {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        message: "Token has been revoked. Please login again.",
      });
    }

    const newAccessToken = generateAccessToken(
      user._id,
      user.role,
      user.tokenVersion
    );
    const newRefreshToken = generateRefreshToken(user._id, user.tokenVersion);

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 4 * 24 * 60 * 60 * 1000, // 4 days
    });

    return res.status(StatusCodes.OK).json({
      message: "Token refreshed successfully!",
      accessToken: newAccessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: "Internal server error.",
      error: error.message,
    });
  }
}

export async function logoutHandler(req, res) {
  try {
    res.clearCookie("refreshToken", { path: "/" });
    return res.status(StatusCodes.OK).json({
      message: "Logged out successfully!",
    });
  } catch (error) {
    console.log(error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: "Internal server error.",
      error: error.message,
    });
  }
}

export async function forgotPassword(req, res) {
  try {
    const email = req?.body?.email;

    if (!email) {
      return res.status(StatusCodes.BAD_REQUEST).json({
        message: "Email is required.",
      });
    }

    const normalizeEmail = email.toLocaleLowerCase().trim();
    const user = await User.findOne({ email: normalizeEmail });
    if (!user) {
      return res.status(StatusCodes.NOT_FOUND).json({
        message:
          "If an account with that email exists, a password reset link has been sent.",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");

    const hashedToken = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 min

    await user.save();

    const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;

    await sendEmail(
      user.email,
      "Password Reset Request",
      `<p>Click the link below to reset your password:</p>
      <a href="${resetUrl}">${resetUrl}</a>
      <p>This link will expire in 15 minutes.</p>`
    );

    return res.status(StatusCodes.OK).json({
      message:
        "If an account with that email exists, a password reset link has been sent.",
    });
  } catch (error) {
    console.log(error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: "Internal server error.",
      error: error.message,
    });
  }
}

export async function resetPasswordHandler(req, res) {
  try {
    const { token, newPassword } = req.body;

    if (!token) {
      return res.status(StatusCodes.BAD_REQUEST).json({
        message: "reset token is missing.",
      });
    }

    if (!newPassword || newPassword.length < 6) {
      return res.status(StatusCodes.BAD_REQUEST).json({
        message:
          "New password is required and should be at least 6 characters long.",
      });
    }

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(StatusCodes.BAD_REQUEST).json({
        message: "Invalid or expired password reset token.",
      });
    }

    const hashedPassword = await hashPassword(newPassword);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    user.tokenVersion += 1;

    await user.save();

    return res.status(StatusCodes.OK).json({
      message: "Password has been reset successfully!",
    });
  } catch (error) {
    console.log(error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: "Internal server error.",
      error: error.message,
    });
  }
}

export function getGoogleOAuthHandler(req, res) {
  try {
    const client = getGoogleClient();

    const url = client.generateAuthUrl({
      access_type: "offline",
      scope: ["openid", "profile", "email"],
      prompt: "consent",
    });

    return res.redirect(url);
  } catch (error) {
    console.log(error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: "Internal server error.",
      error: error.message,
    });
  }
}

export async function googleOAuthCallbackHandler(req, res) {
  try {
    const code = req.query.code;

    if (!code) {
      return res.status(StatusCodes.BAD_REQUEST).json({
        message: "Authorization code is missing.",
      });
    }

    const client = getGoogleClient();

    const { tokens } = await client.getToken(code);

    if (!tokens.id_token) {
      return res.status(StatusCodes.BAD_REQUEST).json({
        message: "ID token is missing in Google's response.",
      });
    }

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.OATH_GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    const email = payload.email.toLowerCase();
    const emailVerified = payload.email_verified;

    if (!email || !emailVerified) {
      return res.status(StatusCodes.FORBIDDEN).json({
        message: "Google account email is not verified.",
      });
    }

    const normalizeEmail = email.toLocaleLowerCase().trim();
    let user = await User.findOne({ email: normalizeEmail });

    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString("hex");
      const passwordHash = await hashPassword(randomPassword);

      user = new User({
        email: normalizeEmail,
        name: payload.name || "No Name",
        password: passwordHash,
        role: "user",
        isEmailVerified: true,
      });

      await user.save();
    } else {
      if (!user.isEmailVerified) {
        user.isEmailVerified = true;
        await user.save();
      }
    }

    const accessToken = generateAccessToken(
      user._id,
      user.role,
      user.tokenVersion
    );
    const refreshToken = generateRefreshToken(user._id, user.tokenVersion);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 4 * 24 * 60 * 60 * 1000, // 4 days
    });

    return res.status(StatusCodes.OK).json({
      message: "Google Login successful!",
      accessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      message: "Internal server error.",
      error: error.message,
    });
  }
}
