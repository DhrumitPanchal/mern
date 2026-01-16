import z from "zod";

const registerSchema = z.object({
  email: z.email(),
  name: z.string().min(3),
  password: z.string().min(6),
});

const loginSchema = z.object({
  email: z.email(),
  password: z.string().min(6),
});

export { registerSchema, loginSchema };
