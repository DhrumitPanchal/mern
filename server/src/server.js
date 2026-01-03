import http from "node:http";
import { ConnectDB } from "./config/dbconnect.js";
import variables from "./lib/envVariables.js";
import app from "./app.js";

async function startServer(params) {
  await ConnectDB();

  const Server = http.createServer(app);

  Server.listen(variables.PORT, () => {
    console.log(`Server is running on port : ${variables.PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Error while staring server." + err);
  process.exit(1);
});
