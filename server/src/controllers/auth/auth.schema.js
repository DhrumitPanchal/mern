import z from "zod";

const registerSchema = z.object({
    email : z.email(),
    name : z.string().min(3),
    
})