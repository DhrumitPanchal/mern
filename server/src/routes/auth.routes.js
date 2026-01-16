import { Router } from "express";
import {
  forgotPassword,
  getGoogleOAuthHandler,
  googleOAuthCallbackHandler,
  loginHandler,
  logoutHandler,
  refreshHandler,
  registerHandler,
  resetPasswordHandler,
  verifyEmailHandler,
} from "../controllers/auth/auth.controller.js";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler);
router.get("/verify-email", verifyEmailHandler);
router.post("/refresh", refreshHandler);
router.post("/logout", logoutHandler);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPasswordHandler);
router.get("/google-auth", getGoogleOAuthHandler);
router.get("/google/callback", googleOAuthCallbackHandler);

export default router;
