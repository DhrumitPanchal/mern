import { StatusCodes } from "http-status-codes";
function isAdmin(role) {
  return (req, res, next) => {
    const authReq = req.user;

    if (!authReq) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ message: "User not authenticated" });
    }

    if (authReq.role !== role) {
      res
        .status(StatusCodes.FORBIDDEN)
        .json({ message: "Access denied. Admins only." });
    }

    next();
  };
}

export default isAdmin;
