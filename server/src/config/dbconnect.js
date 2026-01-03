import mongoose from "mongoose";
import variables from "../lib/envVariables.js";
import dotenv from "dotenv";

dotenv.config();
export async function ConnectDB() {
  try {
    mongoose.connect(variables.MONGODB_URL);
    console.log("DB connected successfully.");
  } catch (error) {
    console.error("DB connection error.");
    process.exit(1);
  }
}
