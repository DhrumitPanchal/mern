const { default: mongoose } = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      require: true,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamp: true,
  }
);

export const User = mongoose.model("User", userSchema);
