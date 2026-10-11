const bcrypt = require("bcryptjs");
const readline = require("readline");
const rl = readline.createInterface({input:process.stdin,output:process.stdout});
rl.question("Enter a strong admin password (min 12 characters): ", async p=>{
  rl.close();
  if (p.length < 12) { console.error("Password too short."); process.exit(1); }
  console.log("\nSet this as ADMIN_PASSWORD_HASH in your hosting environment:\n");
  console.log(await bcrypt.hash(p, 12));
});
