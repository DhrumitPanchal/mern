import { Router } from "express";
import requireAuth from "../middleware/requiredAuth.js";
import isAdmin from "../middleware/isAdmin.js";

const router = Router();

router.get("/me", requireAuth, (req, res) => {
  const authReq = req;
  res.json({ user: authReq.user });
});

router.get("/admin", requireAuth, isAdmin("admin"), (req, res) => {
  res.json({ message: "Welcome, Admin!" });
});

export default router;
