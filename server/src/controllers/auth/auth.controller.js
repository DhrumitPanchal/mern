import { User } from "../../models/user.model";
import { registerSchema } from "./auth.schema";

export async function registerHandler(req, res) {
  try {
    const result = registerSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data!",
        error: result.error.flatten(),
      });
    }

    const { email, name, password } = result.data;

    const normalizeEmail = email.toLocaleLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizeEmail });

    if (existingUser) {
      return res.status(409).json({
        message: "Email is already in use! please try with different email",
      });
    }
  } catch (error) {}
}
